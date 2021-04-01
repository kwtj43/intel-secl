/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/vs"
	vsPlugin "github.com/intel-secl/intel-secl/v3/pkg/ihub/attestationPlugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	"github.com/spf13/viper"
)

func TestDownloadSamlCertValidate(t *testing.T) {

	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()
	time.Sleep(1 * time.Second)
	c1 := testutility.SetupMockK8sConfiguration(t, port)
	c2 := testutility.SetupMockK8sConfiguration(t, port)
	c2.AttestationService.AttestationURL = c2.AttestationService.AttestationURL + "/e"

	temp, err := ioutil.TempFile("", "samlCert.pem")
	if err != nil {
		t.Log("tasks/download_saml_cert_test:TestDownloadSamlCertValidate() : Unable to read file", err)
	}
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Error("Error removing file")
		}
	}()
	tests := []struct {
		name    string
		d       DownloadSamlCert
		wantErr bool
	}{
		{
			name: "download-saml-cert-validate valid test",
			d: DownloadSamlCert{
				AttestationConfig: &c1.AttestationService,
				SamlCertPath:      temp.Name(),
				ConsoleWriter:     os.Stdout,
			},
			wantErr: false,
		}, {
			name: "download-saml-cert-validate negative test",
			d: DownloadSamlCert{
				AttestationConfig: &c2.AttestationService,
				SamlCertPath:      "",
				ConsoleWriter:     os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.d.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/download_saml_cert_test:TestDownloadSamlCertValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadSamlCertRun(t *testing.T) {
	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()
	time.Sleep(1 * time.Second)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	tempSamlFile, err := ioutil.TempFile("", "samlCert.pem")
	if err != nil {
		t.Errorf("tasks/download_saml_cert_test:TestDownloadSamlCertRun() unable to create samlecert.pem temp file %v", err)
	}
	defer func() {
		cerr := tempSamlFile.Close()
		if cerr != nil {
			t.Errorf("Error closing file: %v", cerr)
		}
		derr := os.Remove(tempSamlFile.Name())
		if derr != nil {
			t.Errorf("Error removing file : %v", derr)
		}
	}()
	tests := []struct {
		name      string
		d         DownloadSamlCert
		EnvValues map[string]string
		wantErr   bool
	}{
		{
			name: "download-saml-cert-run valid test",
			d: DownloadSamlCert{
				AttestationConfig: &config.AttestationConfig{},
				SamlCertPath:      tempSamlFile.Name(),
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_TYPE":        "HVS",
				"ATTESTATION_SERVICE_URL": "http://localhost" + port + "/mtwilson/v2/",
			},
			wantErr: false,
		},

		{
			name: "download-saml-cert-run negative test",
			d: DownloadSamlCert{
				AttestationConfig: &config.AttestationConfig{},
				SamlCertPath:      "",
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_TYPE":        "HVS",
				"ATTESTATION_SERVICE_URL": "http://localhost" + port + "/mtwilson/v2/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		vsPlugin.VsClient = &vs.Client{}
		t.Run(tt.name, func(t *testing.T) {
			for key := range tt.EnvValues {
				os.Unsetenv(key)
				os.Setenv(key, tt.EnvValues[key])
				defer func() {
					derr := os.Unsetenv(key)
					if derr != nil {
						t.Errorf("Error unseting ENV :%v", derr)
					}
				}()
			}

			if err := tt.d.Run(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/download_saml_cert_test:TestDownloadSamlCertRun() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
