/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package attestationPlugin

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/skchvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"

	"github.com/pkg/errors"
)

//SGXClient Client for SGX
var SGXClient = &skchvsclient.Client{}

//SGXHost Registered host details on SGX
type SGXHost []struct {
	ConnectionString string `json:"connection_string"`
	HostID           string `json:"host_ID"`
	HostName         string `json:"host_name"`
	UUID             string `json:"uuid"`
}

//Retrieve platform data from SGX attestation service
func GetHostPlatformData(hostName string, config *config.Configuration, certDirectory string) ([]byte, error) {
	log.Trace("attestationPlugin/sgx_plugin:GetHostPlatformData() Entering")
	defer log.Trace("attestationPlugin/sgx_plugin:GetHostPlatformData() Leaving")

	url := config.AttestationService.AttestationURL + "/platform-data" + "?HostName=%s"

	url = fmt.Sprintf(url, strings.ToLower(hostName))

	sgxClient, err := initializeSKCClient(config, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:GetHostPlatformData() Error in initialising SKCHVS client")
	}

	platformData, err := sgxClient.GetSGXPlatformData(url)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:GetHostPlatformData() Error in getting SGX platform details")
	}

	return platformData, nil
}

//Get SGX HVS version to validate IHUB connection with SGX attestation service
func GetSHVSVersion(config *config.Configuration, certDirectory string) ([]byte, error) {
	log.Trace("attestationPlugin/sgx_plugin:GetSHVSVersion() Entering")
	defer log.Trace("attestationPlugin/sgx_plugin:GetSHVSVersion() Leaving")

	url := config.AttestationService.AttestationURL + "/" + "version"

	sgxClient, err := initializeSKCClient(config, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:GetSHVSVersion() Error in initializing SHVS Client")
	}

	version, err := sgxClient.GetSHVSVersion(url)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:GetSHVSVersion() Error in getting version information")
	}

	return version, nil
}

//initializeSKCClient method used to initialize the client
func initializeSKCClient(con *config.Configuration, certDirectory string) (*skchvsclient.Client, error) {
	log.Trace("attestationPlugin/sgx_plugin:initializeSKCClient() Entering")
	defer log.Trace("attestationPlugin/sgx_plugin:initializeSKCClient() Leaving")

	if SGXClient != nil && SGXClient.AASURL != nil && SGXClient.BaseURL != nil {
		return SGXClient, nil
	}

	if len(CertArray) < 0 && certDirectory != "" {
		err := loadCertificates(certDirectory)
		if err != nil {
			return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:initializeSKCClient() Error in initializing certificates")
		}
	}

	aasURL, err := url.Parse(con.AASApiUrl)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:initializeSKCClient() Error parsing AAS URL")
	}

	attestationURL, err := url.Parse(con.AttestationService.AttestationURL)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/sgx_plugin:initializeSKCClient() Error in parsing attestation service URL")
	}

	SGXClient = &skchvsclient.Client{
		AASURL:    aasURL,
		BaseURL:   attestationURL,
		UserName:  con.IHUB.Username,
		Password:  con.IHUB.Password,
		CertArray: CertArray,
	}

	return SGXClient, nil
}
