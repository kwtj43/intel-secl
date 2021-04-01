/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// This init function sets the default values for viper keys.
func init() {
	viper.SetDefault("endpoint-url", constants.DefaultEndpointUrl)
	viper.SetDefault("key-manager", constants.DefaultKeyManager)

	// Set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertPath)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyPath)
	viper.SetDefault("tls-common-name", constants.DefaultKbsTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultKbsTlsSan)

	// Set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", constants.DefaultLogLevel)

	// Set default value for kmip version
	viper.SetDefault("kmip-version", "2.0")

	// Set default values for server
	viper.SetDefault("server-port", constants.DefaultKBSListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl:        viper.GetString("aas-base-url"),
		CMSBaseURL:       viper.GetString("cms-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),

		EndpointURL: viper.GetString("endpoint-url"),
		KeyManager:  viper.GetString("key-manager"),

		KBS: config.KBSConfig{
			UserName: viper.GetString("kbs-service-username"),
			Password: viper.GetString("kbs-service-password"),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		Server: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		Kmip: config.KmipConfig{
			Version:    viper.GetString("kmip-version"),
			ServerIP:   viper.GetString("kmip-server-ip"),
			ServerPort: viper.GetString("kmip-server-port"),
			ClientCert: viper.GetString("kmip-client-cert-path"),
			ClientKey:  viper.GetString("kmip-client-key-path"),
			RootCert:   viper.GetString("kmip-root-cert-path"),
		},
		Skc: config.SKCConfig{
			StmLabel:          viper.GetString("skc-challenge-type"),
			SQVSUrl:           viper.GetString("sqvs-url"),
			SessionExpiryTime: viper.GetInt("session-expiry-time"),
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
