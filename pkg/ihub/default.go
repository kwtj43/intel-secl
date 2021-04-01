/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// This func sets the default values for viper keys
func init() {
	viper.SetDefault("attestation-type", constants.DefaultAttestationType)
	viper.SetDefault("poll-interval-minutes", constants.PollingIntervalMinutes)

	//Set default values for TLS
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultIHUBTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultTLSSan)

	//Set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl:           viper.GetString("aas-base-url"),
		CMSBaseURL:          viper.GetString("cms-base-url"),
		CmsTlsCertDigest:    viper.GetString("cms-tls-cert-sha384"),
		PollIntervalMinutes: viper.GetInt("poll-interval-minutes"),
		IHUB: commConfig.ServiceConfig{
			Username: viper.GetString("ihub-service-username"),
			Password: viper.GetString("ihub-service-password"),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		AttestationService: config.AttestationConfig{
			AttestationType: viper.GetString("attestation-type"),
			AttestationURL:  viper.GetString("attestation-service-url"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			Level:        viper.GetString("log-level"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		"tls-san-list": "SAN_LIST",
		"aas-base-url": "AAS_API_URL",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
