/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package skchvsclient

import (
	"crypto/x509"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/aas"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	"net/url"
	"testing"
)

func TestClientGetSGXPlatformData(t *testing.T) {
	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()
	aasUrl, _ := url.Parse("http://localhost" + port + "/aas")
	baseURL, _ := url.Parse("http://localhost" + port + "/sgx-hvs/v2")

	client1 := Client{
		AASURL:    aasUrl,
		BaseURL:   baseURL,
		Password:  "admin@ihub",
		UserName:  "hubadminpass",
		CertArray: []x509.Certificate{},
	}
	fmt.Println(client1)
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		c       Client
		args    args
		wantErr bool
	}{
		{
			name:    "Valid Test: get-sgx-platform-data using SHVS client",
			c:       client1,
			wantErr: false,
			args: args{
				url: "http://localhost" + port + "/sgx-hvs/v2/platform-data",
			},
		},
	}
	for _, tt := range tests {

		_ = aas.NewJWTClient("")
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.c.GetSGXPlatformData(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("TestClientGetSGXPlatformData() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func TestClientGetSHVSVersion(t *testing.T) {
	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	aasUrl, _ := url.Parse("http://localhost" + port + "/aas")
	baseURL, _ := url.Parse("http://localhost" + port + "/sgx-hvs/v2")

	client1 := Client{
		AASURL:    aasUrl,
		BaseURL:   baseURL,
		Password:  "admin@ihub",
		UserName:  "hubadminpass",
		CertArray: []x509.Certificate{},
	}
	fmt.Println(client1)
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		c       Client
		args    args
		wantErr bool
	}{
		{
			name:    "Valid Test: get-shvs-version using SHVS client",
			c:       client1,
			wantErr: false,
			args: args{
				url: "http://localhost" + port + "/sgx-hvs/v2/version",
			},
		},
	}
	for _, tt := range tests {

		_ = aas.NewJWTClient("")
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.c.GetSHVSVersion(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("TestClientGetSHVSVersion() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}
