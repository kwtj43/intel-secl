/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
)

type UpdateServiceConfig struct {
	ServiceConfig commConfig.ServiceConfig
	AASApiUrl     string
	AppConfig     **config.Configuration
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"SERVICE_USERNAME":  "The service username as configured in AAS",
	"SERVICE_PASSWORD":  "The service password as configured in AAS",
	"LOG_LEVEL":         "Log level",
	"LOG_MAX_LENGTH":    "Max length of log statement",
	"LOG_ENABLE_STDOUT": "Enable console log",
	"AAS_BASE_URL":      "AAS Base URL",
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_config:Run() Entering")
	defer log.Trace("tasks/update_config:Run() Leaving")
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt("log-max-length"),
		EnableStdout: viper.GetBool("log-enable-stdout"),
		Level:        viper.GetString("log-level"),
	}
	if uc.ServiceConfig.Username == "" {
		return errors.New("IHUB configuration not provided: IHUB_SERVICE_USERNAME is not set")
	}
	if uc.ServiceConfig.Password == "" {
		return errors.New("IHUB configuration not provided: IHUB_SERVICE_PASSWORD is not set")
	}
	if uc.AASApiUrl == "" {
		return errors.New("IHUB configuration not provided: AAS_BASE_URL is not set")
	}

	(*uc.AppConfig).IHUB = uc.ServiceConfig
	(*uc.AppConfig).AASApiUrl = uc.AASApiUrl
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt("log-max-length"),
		EnableStdout: viper.GetBool("log-enable-stdout"),
		Level:        viper.GetString("log-level"),
	}

	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	if (*uc.AppConfig).IHUB.Username == "" {
		return errors.New("IHUB username is not set in the configuration")
	}
	if (*uc.AppConfig).IHUB.Password == "" {
		return errors.New("IHUB password is not set in the configuration")
	}
	return nil
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, envHelpPrompt, "", envHelp)
	fmt.Fprintln(w, "")
}

func (uc UpdateServiceConfig) SetName(n, e string) {
}
