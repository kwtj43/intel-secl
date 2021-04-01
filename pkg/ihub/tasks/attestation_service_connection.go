/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"net/url"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/skchvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/spf13/viper"

	"github.com/pkg/errors"
)

// AttestationServiceConnection is a setup task for setting up the connection to the Host Verification Service (Attestation Service)
type AttestationServiceConnection struct {
	AttestationConfig *config.AttestationConfig
	ConsoleWriter     io.Writer
}

// Run will run the Attestation Service Connection setup task, but will skip if Validate() returns no errors
func (attestationService AttestationServiceConnection) Run() error {
	fmt.Fprintln(attestationService.ConsoleWriter, "Setting up Attestation Service Connection...")

	attestationType := viper.GetString("attestation-type")
	attestationURL := viper.GetString("attestation-service-url")

	if attestationURL == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing attestation service endpoint url in environment")
	}

	if attestationType == "" {
		attestationType = constants.DefaultAttestationType
		fmt.Fprintln(attestationService.ConsoleWriter, "Attestation type is not defined in environment, default attestation type set")
	}

	attestationService.AttestationConfig.AttestationType = attestationType
	attestationService.AttestationConfig.AttestationURL = attestationURL

	return nil
}

// Validate checks whether or not the Attestation Service Connection setup task was completed successfully
func (attestationService AttestationServiceConnection) Validate() error {
	if attestationService.AttestationConfig.AttestationType == "" {
		return errors.New("tasks/attestation_service_connection:Validate() Attestation service connection: Attestation type is not set")
	}

	if attestationService.AttestationConfig.AttestationURL == "" {
		return errors.New("tasks/attestation_service_connection:Validate() Attestation service Connection: Attestation url is not set")
	}

	//validating the service url
	return attestationService.validateService()
}

//validateService Validates the attestation service connection is successful or not by hitting the service url's
func (attestationService AttestationServiceConnection) validateService() error {

	if attestationService.AttestationConfig.AttestationType == "HVS" {
		baseURL, err := url.Parse(attestationService.AttestationConfig.AttestationURL)
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error in parsing attestation service URL")
		}

		vsClient := &vs.Client{
			BaseURL: baseURL,
		}

		_, err = vsClient.GetCaCerts("saml")
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting response from attestation service")
		}

	} else if attestationService.AttestationConfig.AttestationType == "SGX" {
		versionURL := attestationService.AttestationConfig.AttestationURL + "/" + "version"
		shvsClient := &skchvsclient.Client{}

		_, err := shvsClient.GetSHVSVersion(versionURL)
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting response from SGX attestation service")
		}
	} else {
		return errors.New("tasks/attestation_service_connection:validateService() Attestation type is not supported")
	}

	fmt.Fprintln(attestationService.ConsoleWriter, "Attestation Service Connection is successful")
	return nil
}

//PrintHelp Prints the help message
func (attestationService AttestationServiceConnection) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"ATTESTATION_TYPE":        "Type of Attestation Service",
		"ATTESTATION_SERVICE_URL": "Base URL for the Attestation Service",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for attestation-service-connection setup:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (attestationService AttestationServiceConnection) SetName(n, e string) {}
