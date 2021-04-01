/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package attestationPlugin

import (
	"encoding/xml"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
)

var sampleSamlCertPath = testutility.SampleSamlCertPath
var sampleSamlReportPath = testutility.SampleSamlReportPath
var sampleRootCertDirPath = "../test/resources/trustedCACert"
var hostID = testutility.OpenstackHostID
var invalidHostID = testutility.InvalidOpenstackHostID

func TestGetHostReports(t *testing.T) {

	server, portString := testutility.MockServer(t)
	c := testutility.SetupMockK8sConfiguration(t, portString)
	report, err := ioutil.ReadFile(sampleSamlReportPath)
	if err != nil {
		t.Log("attestationPlugin/vs_plugin_test:TestGetHostReports() : Unable to read file")
	}

	samlReport := &saml.Saml{}
	err = xml.Unmarshal(report, samlReport)

	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()
	type args struct {
		h string
		c *config.Configuration
	}
	tests := []struct {
		name string
		args args
		want *saml.Saml
	}{
		{
			name: "TestGetHostReports Test 1",
			args: args{
				h: hostID,
				c: c,
			},
			want: samlReport,
		},
		{
			name: "TestGetHostReports Test 2",
			args: args{
				h: invalidHostID,
				c: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS", AttestationURL: "http://localhost" + portString + "/mtwilson/v2/invalid",
					},
					Endpoint: config.Endpoint{
						Type:     "OPENSTACK",
						URL:      "http://localhost" + portString + "/openstack/api/",
						AuthURL:  "http://localhost" + portString + "/v3/auth/tokens",
						UserName: testutility.OpenstackUserName,
						Password: testutility.OpenstackPassword,
					},
					IHUB: commConfig.ServiceConfig{
						Username: testutility.IhubServiceUserName,
						Password: testutility.IhubServicePassword,
					},
				},
			},
			want: nil,
		},
		{
			name: "TestGetHostReports Test 3",
			args: args{
				h: hostID,
				c: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS", AttestationURL: "http://localhost" + portString + "/mtwilson/v2",
					},
					Endpoint: config.Endpoint{
						Type:     "OPENSTACK",
						URL:      "http://localhost" + portString + "/openstack/api/",
						AuthURL:  "http://localhost" + portString + "/v3/auth/tokens",
						UserName: testutility.OpenstackUserName,
						Password: testutility.OpenstackPassword,
					},
					IHUB: commConfig.ServiceConfig{
						Username: testutility.IhubServiceUserName,
						Password: testutility.IhubServicePassword,
					},
				},
			},

			want: samlReport,
		},

		{
			name: "TestGetHostReports Test 4",
			args: args{
				h: hostID,
				c: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS", AttestationURL: "mtwilson/v2"},
					Endpoint: config.Endpoint{
						Type: "OPENSTACK",
					},
				},
			},

			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args
			// TODO need to create a mock saml report verifier since we already have the saml report verifier test
			// or we need to move all resources like saml cert, saml report to common folder
			got, _ := GetHostReports(tArgs.h, tArgs.c, sampleRootCertDirPath, sampleSamlCertPath)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("attestationPlugin/vs_plugin_test:TestGetHostReports()  got = %v, want: %v", got != nil, tt.want != nil)
			}
		})
	}
}

func TestGetCaCerts(t *testing.T) {
	samlCert, err := ioutil.ReadFile(sampleSamlCertPath)
	samlCertificate := string(samlCert)
	if err != nil {
		t.Log("attestationPlugin/vs_plugin_test:TestGetCaCerts() : Unable to read file")
	}

	server, portString := testutility.MockServer(t)

	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	type args struct {
		domain        string
		configuration *config.Configuration
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "Validate CA certificate for SAML 1",
			args: args{
				domain: "SAML",
				configuration: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS",
						AttestationURL:  "",
					},
				},
			},
			want: nil,
		},

		{
			name: "Validate CA certificate for SAML 2",
			args: args{
				domain: "SAML",
				configuration: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS",
						AttestationURL:  "http://localhost" + portString + "/mtwilson/v2",
					},
				},
			},
			want: []byte(samlCertificate),
		},
	}

	for _, tt := range tests {
		VsClient = &vs.Client{}
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args

			got1, _ := GetCaCerts(tArgs.domain, tArgs.configuration, "")

			if !reflect.DeepEqual(got1, tt.want) {
				t.Errorf("attestationPlugin/vs_plugin_test:TestGetCaCerts() got1 = %v, want1: %v", got1, tt.want)
			}
		})
	}
}

func Test_initializeCert(t *testing.T) {

	type args struct {
		certDirectory string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test_initializeCert Test 1",
			args: args{
				certDirectory: "",
			},
			wantErr: true,
		},
		{
			name: "Test_initializeCert Test 2",
			args: args{
				certDirectory: "../test/resources/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := loadCertificates(tt.args.certDirectory); (err != nil) != tt.wantErr {
				t.Errorf("attestation_plugin/vs_plugin_test:loadCertificates() Error in initializing cert :error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_initializeClient(t *testing.T) {
	server, portString := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()
	type args struct {
		con           *config.Configuration
		certDirectory string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{

		{
			name: "Test_initializeClient Test 1",
			args: args{
				certDirectory: "",
				con: &config.Configuration{
					AASApiUrl: "http://localhost" + portString + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationType: "HVS",
						AttestationURL:  "http://localhost" + portString + "/mtwilson/v2",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		VsClient = &vs.Client{}
		t.Run(tt.name, func(t *testing.T) {
			_, err := initializeClient(tt.args.con, tt.args.certDirectory)
			if (err != nil) != tt.wantErr {
				t.Errorf("attestationPlugin/vs_plugin_test:initializeClient() Error in initializing client :error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
