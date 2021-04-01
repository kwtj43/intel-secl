/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/config"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
)

type UpdateServiceConfig struct {
	AppConfig     **config.Configuration
	ServerConfig  commConfig.ServerConfig
	DefaultPort   int
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"LOG_LEVEL":                           "Log level",
	"LOG_MAX_LENGTH":                      "Max length of log statement",
	"LOG_ENABLE_STDOUT":                   "Enable console log",
	"JWT_INCLUDE_KID":                     "Includes JWT Key Id for token validation",
	"JWT_TOKEN_DURATION_MINS":             "Validity of token duration",
	"JWT_CERT_COMMON_NAME":                "Common Name for JWT Certificate",
	"AUTH_DEFENDER_MAX_ATTEMPTS":          "Auth defender maximum attempts",
	"AUTH_DEFENDER_INTERVAL_MINS":         "Auth defender interval in minutes",
	"AUTH_DEFENDER_LOCKOUT_DURATION_MINS": "Auth defender lockout duration in minutes",
	"SERVER_PORT":                         "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":                 "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT":          "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":                "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":                 "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":             "Max Length Of Request Header in Bytes",
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_config:Run() Entering")
	defer log.Trace("tasks/update_config:Run() Leaving")
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt("log-max-length"),
		EnableStdout: viper.GetBool("log-enable-stdout"),
		Level:        viper.GetString("log-level"),
	}

	(*uc.AppConfig).JWT = config.JWT{
		IncludeKid:        viper.GetBool("jwt-include-kid"),
		TokenDurationMins: viper.GetInt("jwt-token-duration-mins"),
		CertCommonName:    viper.GetString("jwt-cert-common-name"),
	}

	(*uc.AppConfig).AuthDefender = config.AuthDefender{
		MaxAttempts:         viper.GetInt("auth-defender-max-attempts"),
		IntervalMins:        viper.GetInt("auth-defender-interval-mins"),
		LockoutDurationMins: viper.GetInt("auth-defender-lockout-duration-mins"),
	}
	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 {
		uc.ServerConfig.Port = uc.DefaultPort
	}
	(*uc.AppConfig).Server = uc.ServerConfig
	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	if (*uc.AppConfig).Server.Port < 1024 ||
		(*uc.AppConfig).Server.Port > 65535 {
		return errors.New("Configured port is not valid")
	}

	return nil
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, envHelpPrompt, "", envHelp)
	fmt.Fprintln(w, "")
}

func (uc UpdateServiceConfig) SetName(n, e string) {
}
