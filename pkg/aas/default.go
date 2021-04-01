/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"github.com/intel-secl/intel-secl/v3/pkg/aas/config"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
	"os"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultAasTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultAasTlsSan)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxLength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

	// set default for database config
	viper.SetDefault("db-vendor", constants.DefaultDBVendor)
	viper.SetDefault("db-host", "localhost")
	viper.SetDefault("db-port", 5432)
	viper.SetDefault("db-name", constants.DefaultDBName)
	viper.SetDefault("db-ssl-mode", constants.SslModeVerifyFull)
	viper.SetDefault("db-ssl-cert", constants.DefaultSSLCertFilePath)
	viper.SetDefault("db-conn-retry-attempts", constants.DefaultDbConnRetryAttempts)
	viper.SetDefault("db-conn-retry-time", constants.DefaultDbConnRetryTime)

	//set default for JWT and JWT signing cert
	viper.SetDefault("jwt-include-kid", true)
	viper.SetDefault("jwt-cert-common-name", constants.DefaultAasJwtCn)
	viper.SetDefault("jwt-token-duration-mins", constants.DefaultAasJwtDurationMins)

	viper.SetDefault("auth-defender-max-attempts", constants.DefaultAuthDefendMaxAttempts)
	viper.SetDefault("auth-defender-interval-mins", constants.DefaultAuthDefendIntervalMins)
	viper.SetDefault("auth-defender-lockout-duration-mins", constants.DefaultAuthDefendLockoutMins)

}

func defaultConfig() *config.Configuration {
	// support old AAS env
	loadAlias()
	return &config.Configuration{
		CMSBaseURL:       viper.GetString("cms-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
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
		JWT: config.JWT{
			IncludeKid:        viper.GetBool("jwt-include-kid"),
			TokenDurationMins: viper.GetInt("jwt-token-duration-mins"),
			CertCommonName:    viper.GetString("jwt-cert-common-name"),
		},
		AuthDefender: config.AuthDefender{
			MaxAttempts:         viper.GetInt("auth-defender-max-attempts"),
			IntervalMins:        viper.GetInt("auth-defender-interval-mins"),
			LockoutDurationMins: viper.GetInt("auth-defender-lockout-duration-mins"),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		"db-host":                    "AAS_DB_HOSTNAME",
		"db-vendor":                  "AAS_DB_VENDOR",
		"db-port":                    "AAS_DB_PORT",
		"db-name":                    "AAS_DB_NAME",
		"db-username":                "AAS_DB_USERNAME",
		"db-password":                "AAS_DB_PASSWORD",
		"db-ssl-cert":                "AAS_DB_SSLCERT",
		"db-ssl-cert-source":         "AAS_DB_SSLCERTSRC",
		"db-ssl-mode":                "AAS_DB_SSL_MODE",
		"tls-common-name":            "AAS_TLS_CERT_CN",
		"tls-san-list":               "SAN_LIST",
		"server-port":                "AAS_PORT",
		"server-read-timeout":        "AAS_SERVER_READ_TIMEOUT",
		"server-read-header-timeout": "AAS_SERVER_READ_HEADER_TIMEOUT",
		"server-write-timeout":       "AAS_SERVER_WRITE_TIMEOUT",
		"server-idle-timeout":        "AAS_SERVER_IDLE_TIMEOUT",
		"server-max-header-bytes":    "AAS_SERVER_MAX_HEADER_BYTES",
		"aas-service-username":       "AAS_ADMIN_USERNAME",
		"aas-service-password":       "AAS_ADMIN_PASSWORD",
		"jwt-token-duration-mins":    "AAS_JWT_TOKEN_DURATION_MINS",
		"jwt-include-kid":            "AAS_JWT_INCLUDE_KEYID",
		"jwt-cert-common-name":       "AAS_JWT_CERT_CN",
		"tls-cert-file":              "CERT_PATH",
		"tls-key-file":               "KEY_PATH",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
