/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	clog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"time"
)

var log = clog.GetDefaultLogger()

const (
	ServiceUserName                = "cms"
	ServiceName                    = "CMS"
	ExplicitServiceName            = "Certificate Management Service"
	ApiVersion                     = "/v1"
	HomeDir                        = "/opt/cms/"
	ConfigDir                      = "/etc/cms/"
	ExecLinkPath                   = "/usr/bin/cms"
	RunDirPath                     = "/run/cms"
	LogDir                         = "/var/log/cms/"
	DefaultConfigFilePath          = ConfigDir + "config.yml"
	ConfigFile                     = "config"
	TokenKeyFile                   = "cms-jwt.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "jwt/"
	RootCADirPath                  = ConfigDir + "root-ca/"
	RootCACertPath                 = RootCADirPath + "root-ca-cert.pem"
	RootCAKeyPath                  = ConfigDir + "root-ca.key"
	IntermediateCADirPath          = ConfigDir + "intermediate-ca/"
	TLSCertPath                    = ConfigDir + "tls-cert.pem"
	TLSKeyPath                     = ConfigDir + "tls.key"
	SerialNumberPath               = ConfigDir + "serial-number"
	ServiceRemoveCmd               = "systemctl disable cms"
	DefaultRootCACommonName        = "CMSCA"
	DefaultPort                    = 8445
	DefaultOrganization            = "INTEL"
	DefaultCountry                 = "US"
	DefaultProvince                = "SF"
	DefaultLocality                = "SC"
	DefaultCACertValidity          = 5
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	CertApproverGroupName          = "CertApprover"
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasTlsCn                = "AAS TLS Certificate"
	DefaultTlsSan                  = "127.0.0.1,localhost"
	DefaultTokenDurationMins       = 240
	DefaultJwtValidateCacheKeyMins = 60
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxlength       = 300
)

type CaAttrib struct {
	CommonName string
	CertPath   string
	KeyPath    string
}

const (
	Root      = "root"
	Tls       = "TLS"
	TlsClient = "TLS-Client"
	Signing   = "Signing"
)

var mp = map[string]CaAttrib{
	Root:      {"CMSCA", RootCACertPath, RootCAKeyPath},
	Tls:       {"CMS TLS CA", IntermediateCADirPath + "tls-ca.pem", IntermediateCADirPath + "tls-ca.key"},
	TlsClient: {"CMS TLS Client CA", IntermediateCADirPath + "tls-client-ca.pem", IntermediateCADirPath + "tls-client-ca.key"},
	Signing:   {"CMS Signing CA", IntermediateCADirPath + "signing-ca.pem", IntermediateCADirPath + "signing-ca.key"},
}

func GetIntermediateCAs() []string {
	log.Trace("constants/constants:GetIntermediateCAs() Entering")
	defer log.Trace("constants/constants:GetIntermediateCAs() Leaving")

	return []string{Tls, TlsClient, Signing}
}

func GetCaAttribs(t string) CaAttrib {
	log.Trace("constants/constants:GetCaAttribs() Entering")
	defer log.Trace("constants/constants:GetCaAttribs() Leaving")

	if val, found := mp[t]; found {
		return val
	}
	return CaAttrib{}
}
