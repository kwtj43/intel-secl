/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	"github.com/spf13/viper"
)

func TestAttestationServiceConnectionRun(t *testing.T) {
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

	tests := []struct {
		name               string
		attestationService AttestationServiceConnection
		EnvValues          map[string]string
		wantErr            bool
	}{

		{
			name: "test-attestation-service-connection valid test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_TYPE":        "HVS",
				"ATTESTATION_SERVICE_URL": "http://localhost" + port + "/mtwilson/v2/",
			},

			wantErr: false,
		},

		{
			name: "test-attestation-service-connection valid test 2",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_TYPE":        "SGX",
				"ATTESTATION_SERVICE_URL": "http://localhost" + port + "/sgx-hvs/v2/",
			},

			wantErr: false,
		},

		{
			name: "test-attestation-service-connection negative test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_TYPE":        "SKC",
				"ATTESTATION_SERVICE_URL": "",
			},

			wantErr: true,
		},

		{
			name: "test-attestation-service-connection negative test 2",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{},

			wantErr: true,
		},
	}
	for _, tt := range tests {
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

			if err := tt.attestationService.Run(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/attestation_service_connection_test:TestAttestationServiceConnectionRun() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAttestationServiceConnectionValidate(t *testing.T) {

	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	time.Sleep(1 * time.Second)

	tests := []struct {
		name               string
		attestationService AttestationServiceConnection
		wantErr            bool
	}{

		{
			name: "attestation-service-connection-validate valid test",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					AttestationType: "HVS", AttestationURL: "http://localhost" + port + "/mtwilson/v2",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: false,
		},
		{
			name: "attestation-service-connection-validate negative test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					AttestationType: "HVS", AttestationURL: "",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "attestation-service-connection-validate negative test 2",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					AttestationType: "SKC", AttestationURL: "",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := tt.attestationService.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/attestation_service_connection_test:TestAttestationServiceConnectionValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
