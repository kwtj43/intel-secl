/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

//DownloadSamlCert task for downloading SAML Certificate
type DownloadSamlCert struct {
	AttestationConfig *config.AttestationConfig
	ConsoleWriter     io.Writer
	SamlCertPath      string
}

//Run Runs the setup Task
func (samlCert DownloadSamlCert) Run() error {

	attestationType := viper.GetString("attestation-type")
	attestationURL := viper.GetString("attestation-service-url")

	if attestationType == "SGX" {
		fmt.Fprintln(samlCert.ConsoleWriter, "Skipping Download SAML Cert Task for attestation type SGX")
		return nil
	} else if attestationType == "" {
		attestationType = constants.DefaultAttestationType
		fmt.Fprintln(samlCert.ConsoleWriter, "Attestation type is not defined in environment, default attestation type set")
	}

	if attestationURL == "" {
		return errors.New("tasks/download_saml_cert:Run() Missing attestation service endpoint url in environment")
	}

	baseURL, err := url.Parse(attestationURL)
	if err != nil {
		return errors.Wrap(err, "tasks/download_saml_cert:Run() Error in parsing attestation service URL")
	}

	vsClient := &vs.Client{
		BaseURL: baseURL,
	}

	caCerts, err := vsClient.GetCaCerts("saml")
	if err != nil {
		return errors.Wrap(err, "tasks/download_saml_cert:Run() Failed to get SAML ca-certificates from HVS")
	}

	//write the output to a file
	err = ioutil.WriteFile(samlCert.SamlCertPath, caCerts, 0640)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_saml_cert:Run() Error while writing file:%s", samlCert.SamlCertPath)
	}
	err = os.Chmod(samlCert.SamlCertPath, 0640)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_saml_cert:Run() Error while changing file permission for file :%s", samlCert.SamlCertPath)
	}

	return nil
}

//Validate validates the downloaded certificate
func (samlCert DownloadSamlCert) Validate() error {

	if samlCert.AttestationConfig.AttestationType == "SGX" {
		fmt.Fprintln(samlCert.ConsoleWriter, "tasks/download_saml_cert:Validate() Skipping download of SAML Cert task for SGX attestation")
		return nil
	}

	if _, err := os.Stat(samlCert.SamlCertPath); os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/download_saml_cert:Validate() saml certificate does not exist")
	}

	_, err := ioutil.ReadFile(samlCert.SamlCertPath)
	if err != nil {
		return errors.Wrap(err, "tasks/download_saml_cert:Validate() Error while reading Saml CA Certificate file")
	}

	return nil
}

func (samlCert DownloadSamlCert) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"ATTESTATION_TYPE":        "Type of Attestation Service",
		"ATTESTATION_SERVICE_URL": "Base URL for the Attestation Service",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for download-saml-cert:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (samlCert DownloadSamlCert) SetName(n, e string) {}
