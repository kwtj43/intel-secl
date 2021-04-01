/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package openstackplugin

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/openstack"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/pkg/errors"
)

var (
	sampleSamlCertPath = "../test/resources/saml_certificate.pem"
	sampleCACertPath   = "../test/resources/trustedCACert"
)

func TestGetHostsFromOpenStack(t *testing.T) {

	server, port := testutility.MockServer(t)

	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	configuration := config.Configuration{}
	openstackIP := "localhost"
	configuration.Endpoint.URL = constants.HTTP + "://" + openstackIP + port + "/"
	configuration.Endpoint.AuthURL = constants.HTTP + "://" + openstackIP + port + "/" + constants.OpenStackAuthenticationAPI
	configuration.Endpoint.UserName = testutility.OpenstackUserName
	configuration.Endpoint.Password = testutility.OpenstackPassword
	configuration.Endpoint.Type = constants.OpenStackTenant
	configuration.AASApiUrl = "http://localhost" + port + "/aas"
	configuration.IHUB.Username = "admin@hub"
	configuration.IHUB.Password = "hubAdminPass"
	configuration.AttestationService.AttestationURL = "http://localhost" + port + "/mtwilson/v2"

	authURL := configuration.Endpoint.AuthURL
	apiURL := configuration.Endpoint.URL
	userName := configuration.Endpoint.UserName
	password := configuration.Endpoint.Password
	certPath := configuration.Endpoint.CertFile

	authUrl, err := url.Parse(authURL)
	if err != nil {
		log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack(): unable to parse the auth url")
		return
	}

	apiUrl, err := url.Parse(apiURL)
	if err != nil {
		log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack(): unable to parse the api url")
		return
	}

	opnstkClient, err := openstack.NewOpenstackClient(authUrl, apiUrl, userName, password, certPath)
	if err != nil {
		log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Error Initializing Openstack Client")
	}

	osdetails := OpenstackDetails{
		Config:          &configuration,
		OpenstackClient: opnstkClient,
	}

	log.Info("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Fetching Hosts from Openstack")
	err = getHostsFromOpenstack(&osdetails)
	if err != nil {
		log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Error in getting Hosts from Openstack")
	}

	log.Info("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Filtering Hosts from Openstack")
	for num := range osdetails.HostDetails {

		samlReport, err := mockGetHostReports(osdetails.HostDetails[num].HostName, osdetails.Config, t)
		err = getCustomTraitsFromSAMLReport(&osdetails.HostDetails[num], samlReport)
		if err != nil {
			log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Error in Filtering Host details for Openstack")
		}
	}
	log.Debug("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Updating Openstack with the host Details : ", osdetails.HostDetails)

	log.Info("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Updating traits to Openstack")
	err = updateOpenstackTraits(&osdetails)
	if err != nil {
		log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestGetHostsFromOpenStack() Error in Filtering Host details for Openstack")
	}

}

func mockGetHostReports(h string, c *config.Configuration, t *testing.T) (*saml.Saml, error) {
	server, port := testutility.MockServer(t)

	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	osurl := "http://localhost" + port + "/mtwilson/v2/reports?latestPerHost=true&hostName=%s"
	method := "GET"

	osurl = fmt.Sprintf(osurl, strings.ToLower(h))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true}, // As this is test code
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, osurl, nil)

	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Accept", "application/samlassertion+xml")
	req.Header.Add("latestPerHost", "true")
	req.Header.Add("Authorization", "Bearer "+testutility.AASToken)

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "openstackplugin/openstack_plugin_test:mockGetHostReports() Error in invoking calls")
	}

	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			t.Errorf("Error closing response: %v", derr)
		}
	}()
	body, err := ioutil.ReadAll(res.Body)

	samlReport := &saml.Saml{}
	err = xml.Unmarshal(body, samlReport)

	return samlReport, err
}

func TestOpenstackPluginInit(t *testing.T) {
	server, port := testutility.MockServer(t)

	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	tests := []struct {
		name          string
		configuration *config.Configuration
		wantErr       bool
	}{

		{
			name:          "Testing for failures 1",
			configuration: &config.Configuration{},
			wantErr:       true,
		},
		{
			name: "Testing for failures 2",
			configuration: &config.Configuration{
				AASApiUrl: "http://localhost" + port + "/aas",
				Endpoint: config.Endpoint{
					Type:     "OPENSTACK",
					URL:      "http://localhost" + port + "/openstack/api/",
					AuthURL:  "http://localhost" + port + "/v3/auth/tokens",
					UserName: testutility.OpenstackUserName,
					Password: testutility.OpenstackPassword,
				},
			},
			wantErr: false,
		},
		{
			name: "Testing for failures 3",
			configuration: &config.Configuration{
				AASApiUrl:          "http://localhost" + port + "/aas",
				AttestationService: config.AttestationConfig{AttestationType: "HVS", AttestationURL: "http://localhost" + port + "/mtwilson/v2"},
			},
			wantErr: true,
		},

		{
			name: "Success with ISecl-HVS Push",
			configuration: &config.Configuration{
				AASApiUrl: "http://localhost" + port + "/aas",
				AttestationService: config.AttestationConfig{
					AttestationType: constants.DefaultAttestationType, AttestationURL: "http://localhost" + port + "/mtwilson/v2"},
				Endpoint: config.Endpoint{
					Type:     "OPENSTACK",
					URL:      "http://localhost" + port + "/openstack/api/",
					AuthURL:  "http://localhost" + port + "/v3/auth/tokens",
					UserName: testutility.OpenstackUserName,
					Password: testutility.OpenstackPassword,
				},
			},
			wantErr: false,
		},

		{
			name: "Success with SGX-HVS Push",
			configuration: &config.Configuration{
				AASApiUrl: "http://localhost" + port + "/aas",
				AttestationService: config.AttestationConfig{
					AttestationType: constants.AttestationTypeSGX, AttestationURL: "http://localhost" + port + "/sgx-hvs/v2"},
				Endpoint: config.Endpoint{
					Type:     "OPENSTACK",
					URL:      "http://localhost" + port + "/openstack/api/",
					AuthURL:  "http://localhost" + port + "/v3/auth/tokens",
					UserName: testutility.OpenstackUserName,
					Password: testutility.OpenstackPassword,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oPlugin := OpenstackDetails{
				Config:             tt.configuration,
				TrustedCAsStoreDir: sampleCACertPath,
				SamlCertFilePath:   sampleSamlCertPath,
			}

			authURL := oPlugin.Config.Endpoint.AuthURL
			apiURL := oPlugin.Config.Endpoint.URL
			userName := oPlugin.Config.Endpoint.UserName
			password := oPlugin.Config.Endpoint.Password
			certPath := oPlugin.Config.Endpoint.CertFile

			authUrl, err := url.ParseRequestURI(authURL)
			if err != nil {
				log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestOpenstackPluginInit() unable to parse OpenStack auth url")
			}

			apiUrl, err := url.ParseRequestURI(apiURL)
			if err != nil {
				log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestOpenstackPluginInit() unable to parse OpenStack api url")
			}

			openstackClient, err := openstack.NewOpenstackClient(authUrl, apiUrl, userName, password, certPath)
			if err != nil {
				log.WithError(err).Error("openstackplugin/openstack_plugin_test:TestOpenstackPluginInit() Error in initializing the OpenStack client")
			}
			oPlugin.OpenstackClient = openstackClient

			err = SendDataToEndPoint(oPlugin)

			if (err != nil) != tt.wantErr {
				t.Errorf("openstackplugin/openstack_plugin_test:TestOpenstackPluginInit() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_deleteNonAssociatedTraits(t *testing.T) {

	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v", derr)
		}
	}()

	openstackIP := "localhost"

	type args struct {
		o *OpenstackDetails
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test 1 Positive Case",
			args: args{
				o: &OpenstackDetails{
					AllCustomTraits: []string{"CUSTOM_ISECL_INDIA", "CUSTOM_ISECL_USA"},
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL:      constants.HTTP + "://" + openstackIP + port + "/",
							AuthURL:  constants.HTTP + "://" + openstackIP + port + "/" + constants.OpenStackAuthenticationAPI,
							Type:     constants.OpenStackTenant,
							UserName: testutility.OpenstackUserName,
							Password: testutility.OpenstackPassword,
							CertFile: "",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		authURL, _ := url.Parse(tt.args.o.Config.Endpoint.AuthURL)
		apiURL, _ := url.Parse(tt.args.o.Config.Endpoint.URL)

		opClient, _ := openstack.NewOpenstackClient(authURL, apiURL, tt.args.o.Config.Endpoint.UserName, tt.args.o.Config.Endpoint.Password, tt.args.o.Config.Endpoint.CertFile)
		tt.args.o.OpenstackClient = opClient

		t.Run(tt.name, func(t *testing.T) {
			if err := deleteNonAssociatedTraits(tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("deleteNonAssociatedTraits() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
