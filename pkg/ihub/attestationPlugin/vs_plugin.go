/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package attestationPlugin

import (
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commonLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/pkg/errors"
	"net/url"
)

var log = commonLog.GetDefaultLogger()

//CertArray Array of Certificates
var CertArray []x509.Certificate

//VsClient Client for VS
var VsClient = &vs.Client{}

//loadCertificates method is used to read the certificates from files
func loadCertificates(certDirectory string) error {
	log.Trace("attestationPlugin/vs_plugin:loadCertificates() Entering")
	defer log.Trace("attestationPlugin/vs_plugin:loadCertificates() Leaving")

	certPems, err := os.GetDirFileContents(certDirectory, "*.pem")
	if err != nil {
		return errors.Wrap(err, "attestationPlugin/vs_plugin:loadCertificates() Error in reading certificate directory")
	}

	for _, certPem := range certPems {
		x509Certificate, err := crypt.GetCertFromPem(certPem)
		if err != nil {
			return errors.Wrap(err, "attestationPlugin/vs_plugin:loadCertificates() Unable to read X509 certificate")
		}
		CertArray = append(CertArray, *x509Certificate)
	}
	return nil
}

//initializeClient method used to initialize the client
func initializeClient(con *config.Configuration, certDirectory string) (*vs.Client, error) {
	log.Trace("attestationPlugin/vs_plugin:initializeClient() Entering")
	defer log.Trace("attestationPlugin/vs_plugin:initializeClient() Leaving")

	if VsClient != nil && VsClient.AASURL != nil && VsClient.BaseURL != nil {
		return VsClient, nil
	}

	if len(CertArray) < 0 && certDirectory != "" {
		err := loadCertificates(certDirectory)
		if err != nil {
			return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:initializeClient() Error in initializing certificates")
		}
	}

	aasURL, err := url.Parse(con.AASApiUrl)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:initializeClient() Error parsing AAS URL")
	}

	attestationURL, err := url.Parse(con.AttestationService.AttestationURL)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:initializeClient() Error in parsing attestation service URL")
	}

	VsClient = &vs.Client{
		AASURL:    aasURL,
		BaseURL:   attestationURL,
		UserName:  con.IHUB.Username,
		Password:  con.IHUB.Password,
		CertArray: CertArray,
	}

	return VsClient, nil
}

//GetHostReports method is used to retrieve the SAML report from HVS
func GetHostReports(h string, conf *config.Configuration, certDirectory, samlCertPath string) (*saml.Saml, error) {
	log.Trace("attestationPlugin/vs_plugin:GetHostReports() Entering")
	defer log.Trace("attestationPlugin/vs_plugin:GetHostReports() Leaving")

	reportUrl := conf.AttestationService.AttestationURL + "/reports?latestPerHost=true&"

	var filterType string
	if conf.Endpoint.Type == constants.OpenStackTenant {
		filterType = "hostName"
	} else {
		filterType = "hostHardwareId"
	}
	reportUrl = reportUrl + filterType + "=%s"
	reportUrl = fmt.Sprintf(reportUrl, h)

	log.Debug("attestationPlugin/vs_plugin:GetHostReports() Reports URL : " + reportUrl)

	vClient, err := initializeClient(conf, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:GetHostReports() Error in initializing vsclient")
	}

	samlReportBytes, err := vClient.GetSamlReports(reportUrl)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:GetHostReports() Error in fetching SAML report")
	}

	if len(samlReportBytes) == 0 {
		return nil, errors.New("attestationPlugin/vs_plugin:GetHostReports() No reports retrieved from HVS for host with " + filterType + " " + h)
	}

	var samlReportUnmarshalled *saml.Saml
	err = xml.Unmarshal(samlReportBytes, &samlReportUnmarshalled)
	if err != nil {
		log.WithError(err).Error("attestationPlugin/vs_plugin:GetHostReports() Error unmarshalling SAML report")
		return nil, errors.New("Error unmarshalling SAML report")
	}

	verified := saml.VerifySamlSignature(string(samlReportBytes), samlCertPath, certDirectory)

	if !verified {
		return nil, errors.New("attestationPlugin/vs_plugin:GetHostReports() SAML verification failed and report is invalid")
	}

	return samlReportUnmarshalled, nil
}

// GetCaCerts method is used to get all the CA certs of HVS
func GetCaCerts(domain string, conf *config.Configuration, certDirectory string) ([]byte, error) {
	log.Trace("attestationPlugin/vs_plugin:GetCaCerts() Entering")
	defer log.Trace("attestationPlugin/vs_plugin:GetCaCerts() Leaving")

	vClient, err := initializeClient(conf, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:GetCaCerts() Error in initializing vsclient")
	}

	cacerts, err := vClient.GetCaCerts(domain)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/vs_plugin:GetCaCerts() Error in fetching CA certificate")
	}

	return cacerts, nil
}
