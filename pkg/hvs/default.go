/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
	"os"
)

const (
	fvsNumberOfVerifiers               = "fvs-number-of-verifiers"
	fvsNumberOfDataFetchers            = "fvs-number-of-data-fetchers"
	fvsSkipFlavorSignatureVerification = "fvs-skip-flavor-signature-verification"
	fvsHostTrustCacheThreshold         = "fvs-host-trust-cache-threshold"
	hrrsRefreshPeriod                  = "hrrs-refresh-period"
	vcssRefreshPeriod                  = "vcss-refresh-period"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultHvsTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultHvsTlsSan)

	// set default values for all other certs
	viper.SetDefault("saml-cert-file", constants.SAMLCertFile)
	viper.SetDefault("saml-key-file", constants.SAMLKeyFile)
	viper.SetDefault("saml-common-name", constants.DefaultSAMLCN)
	viper.SetDefault("saml-issuer-name", constants.DefaultSAMLCertIssuer)
	viper.SetDefault("saml-validity-seconds", constants.DefaultSAMLCertValidity)

	viper.SetDefault("flavor-signing-cert-file", constants.FlavorSigningCertFile)
	viper.SetDefault("flavor-signing-key-file", constants.FlavorSigningKeyFile)
	viper.SetDefault("flavor-signing-common-name", constants.DefaultFlavorSigningCN)

	viper.SetDefault("privacy-ca-cert-file", constants.PrivacyCACertFile)
	viper.SetDefault("privacy-ca-key-file", constants.PrivacyCAKeyFile)
	viper.SetDefault("privacy-ca-common-name", constants.DefaultPrivacyCACN)
	viper.SetDefault("privacy-ca-issuer", constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault("privacy-ca-validity-years", constants.DefaultSelfSignedCertValidityYears)

	viper.SetDefault("endorsement-ca-cert-file", constants.SelfEndorsementCACertFile)
	viper.SetDefault("endorsement-ca-key-file", constants.EndorsementCAKeyFile)
	viper.SetDefault("endorsement-ca-common-name", constants.DefaultEndorsementCACN)
	viper.SetDefault("endorsement-ca-issuer", constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault("endorsement-ca-validity-years", constants.DefaultSelfSignedCertValidityYears)

	viper.SetDefault("tag-ca-cert-file", constants.TagCACertFile)
	viper.SetDefault("tag-ca-key-file", constants.TagCAKeyFile)
	viper.SetDefault("tag-ca-common-name", constants.DefaultTagCACN)
	viper.SetDefault("tag-ca-issuer", constants.DefaultSelfSignedCertIssuer)
	viper.SetDefault("tag-ca-validity-years", constants.DefaultSelfSignedCertValidityYears)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default for audit log
	viper.SetDefault("audit-log-max-row-count", constants.DefaultMaxRowCount)
	viper.SetDefault("audit-log-number-rotated", constants.DefaultNumRotated)
	viper.SetDefault("audit-log-buffer-size", constants.DefaultChannelBufferSize)

	// set default values for privacy ca
	viper.SetDefault("privacy-ca-cert-validity", constants.DefaultPrivacyCACertValidity)
	viper.SetDefault("privacy-ca-id-issuer", constants.DefaultPrivacyCaIdentityIssuer)

	// set default value for aik
	viper.SetDefault("aik-certificate-validity-years", constants.DefaultAikCertificateValidity)

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultHVSListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

	// set default for database ssl certificate
	viper.SetDefault("db-vendor", "postgres")
	viper.SetDefault("db-host", "localhost")
	viper.SetDefault("db-port", "5432")
	viper.SetDefault("db-name", "hvs_db")
	viper.SetDefault("db-ssl-mode", constants.SslModeVerifyFull)
	viper.SetDefault("db-ssl-cert", constants.ConfigDir+"hvsdbsslcert.pem")
	viper.SetDefault("db-conn-retry-attempts", constants.DefaultDbConnRetryAttempts)
	viper.SetDefault("db-conn-retry-time", constants.DefaultDbConnRetryTime)

	// set default for fvs
	viper.SetDefault(fvsNumberOfVerifiers, constants.DefaultFvsNumberOfVerifiers)
	viper.SetDefault(fvsNumberOfDataFetchers, constants.DefaultFvsNumberOfDataFetchers)
	viper.SetDefault(fvsSkipFlavorSignatureVerification, constants.DefaultSkipFlavorSignatureVerification)
	viper.SetDefault(fvsHostTrustCacheThreshold, constants.DefaultHostTrustCacheThreshold)

	viper.SetDefault(constants.HrrsRefreshPeriod, hrrs.DefaultRefreshPeriod)

	viper.SetDefault(constants.VcssRefreshPeriod, constants.DefaultVcssRefreshPeriod)
}

func defaultConfig() *config.Configuration {
	// support old hvs env
	loadAlias()
	return &config.Configuration{
		AASApiUrl:        viper.GetString("aas-base-url"),
		CMSBaseURL:       viper.GetString("cms-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
		Dek:              viper.GetString("data-encryption-key"),
		AikCertValidity:  viper.GetInt("aik-certificate-validity-years"),
		AuditLog: config.AuditLogConfig{
			MaxRowCount: viper.GetInt("audit-log-max-row-count"),
			NumRotated:  viper.GetInt("audit-log-number-rotated"),
			BufferSize:  viper.GetInt("audit-log-buffer-size"),
		},
		HVS: commConfig.ServiceConfig{
			Username: viper.GetString("hvs-service-username"),
			Password: viper.GetString("hvs-service-password"),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		SAML: config.SAMLConfig{
			CommonConfig: commConfig.SigningCertConfig{
				CertFile:   viper.GetString("saml-cert-file"),
				KeyFile:    viper.GetString("saml-key-file"),
				CommonName: viper.GetString("saml-common-name"),
			},
			Issuer:          viper.GetString("saml-issuer-name"),
			ValiditySeconds: viper.GetInt("saml-validity-seconds"),
		},
		FlavorSigning: commConfig.SigningCertConfig{
			CertFile:   viper.GetString("flavor-signing-cert-file"),
			KeyFile:    viper.GetString("flavor-signing-key-file"),
			CommonName: viper.GetString("flavor-signing-common-name"),
		},
		PrivacyCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("privacy-ca-cert-file"),
			KeyFile:      viper.GetString("privacy-ca-key-file"),
			CommonName:   viper.GetString("privacy-ca-common-name"),
			Issuer:       viper.GetString("privacy-ca-issuer"),
			ValidityDays: viper.GetInt("privacy-ca-validity-years"),
		},
		EndorsementCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("endorsement-ca-cert-file"),
			KeyFile:      viper.GetString("endorsement-ca-key-file"),
			CommonName:   viper.GetString("endorsement-ca-common-name"),
			Issuer:       viper.GetString("endorsement-ca-issuer"),
			ValidityDays: viper.GetInt("endorsement-ca-validity-years"),
		},
		TagCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("tag-ca-cert-file"),
			KeyFile:      viper.GetString("tag-ca-key-file"),
			CommonName:   viper.GetString("tag-ca-common-name"),
			Issuer:       viper.GetString("tag-ca-issuer"),
			ValidityDays: viper.GetInt("tag-ca-validity-years"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		HRRS: hrrs.HRRSConfig{
			RefreshPeriod: viper.GetDuration(constants.HrrsRefreshPeriod),
		},
		VCSS: config.VCSSConfig{
			RefreshPeriod: viper.GetDuration(constants.VcssRefreshPeriod),
		},
		FVS: config.FVSConfig{
			NumberOfVerifiers:               viper.GetInt(fvsNumberOfVerifiers),
			NumberOfDataFetchers:            viper.GetInt(fvsNumberOfDataFetchers),
			SkipFlavorSignatureVerification: viper.GetBool(fvsSkipFlavorSignatureVerification),
			HostTrustCacheThreshold:         viper.GetInt(fvsHostTrustCacheThreshold),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		"db-host":                    "HVS_DB_HOSTNAME",
		"db-vendor":                  "HVS_DB_VENDOR",
		"db-port":                    "HVS_DB_PORT",
		"db-name":                    "HVS_DB_NAME",
		"db-username":                "HVS_DB_USERNAME",
		"db-password":                "HVS_DB_PASSWORD",
		"db-ssl-cert":                "HVS_DB_SSLCERT",
		"db-ssl-cert-source":         "HVS_DB_SSLCERTSRC",
		"db-ssl-mode":                "HVS_DB_SSL_MODE",
		"tls-san-list":               "SAN_LIST",
		"aas-base-url":               "AAS_API_URL",
		"server-read-timeout":        "HVS_SERVER_READ_TIMEOUT",
		"server-read-header-timeout": "HVS_SERVER_READ_HEADER_TIMEOUT",
		"server-write-timeout":       "HVS_SERVER_WRITE_TIMEOUT",
		"server-idle-timeout":        "HVS_SERVER_IDLE_TIMEOUT",
		"server-max-header-bytes":    "HVS_SERVER_MAX_HEADER_BYTES",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
