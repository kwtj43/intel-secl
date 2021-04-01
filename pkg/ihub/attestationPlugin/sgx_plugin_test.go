/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package attestationPlugin

import (
	"github.com/intel-secl/intel-secl/v3/pkg/clients/skchvsclient"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
)

func TestGetHostReportsSGX(t *testing.T) {
	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	output, err := ioutil.ReadFile("../../ihub/test/resources/sgx_platform_data.json")
	if err != nil {
		t.Log("attestationPlugin/sgx_plugin_test:TestGetHostReportsSGX(): Unable to read file", err)
	}

	sgxHostName := "localhost"
	type args struct {
		hostIP string
		config *config.Configuration
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Valid Test: get-sgx-host-platform-data",
			args: args{
				hostIP: sgxHostName,
				config: &config.Configuration{
					AASApiUrl: "http://localhost" + port + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationURL: "http://localhost" + port + "/sgx-hvs/v2",
					},
				},
			},
			want:    output,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHostPlatformData(tt.args.hostIP, tt.args.config, sampleRootCertDirPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostReportsSGX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHostReportsSGX() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSHVSVersion(t *testing.T) {

	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	type args struct {
		config *config.Configuration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid Test: get-shvs-version",
			args: args{
				config: &config.Configuration{
					AASApiUrl: "http://localhost" + port + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationURL: "http://localhost" + port + "/sgx-hvs/v2",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetSHVSVersion(tt.args.config, "")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSHVSVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_initializeSKCClient(t *testing.T) {
	server, port := testutility.MockServer(t)
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
			name: "Valid Test: initialize-skc-client",
			args: args{
				certDirectory: "",
				con: &config.Configuration{
					AASApiUrl: "http://localhost" + port + "/aas",
					IHUB: commConfig.ServiceConfig{
						Username: "admin@hub",
						Password: "hubAdminPass",
					},
					AttestationService: config.AttestationConfig{
						AttestationType: "SGX",
						AttestationURL:  "http://localhost" + port + "/sgx-hvs/v2",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		SGXClient = &skchvsclient.Client{}
		t.Run(tt.name, func(t *testing.T) {
			_, err := initializeSKCClient(tt.args.con, tt.args.certDirectory)
			if (err != nil) != tt.wantErr {
				t.Errorf("attestationPlugin/sgx_plugin_test:initializeSKCClient() Error in initializing client :error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
