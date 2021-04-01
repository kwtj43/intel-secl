/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
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
	ServerConfig  commConfig.ServerConfig
	DefaultPort   int
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"SERVICE_USERNAME":                       "The service username as configured in AAS",
	"SERVICE_PASSWORD":                       "The service password as configured in AAS",
	"LOG_LEVEL":                              "Log level",
	"LOG_MAX_LENGTH":                         "Max length of log statement",
	"LOG_ENABLE_STDOUT":                      "Enable console log",
	"AAS_BASE_URL":                           "AAS Base URL",
	"HRRS_REFRESH_PERIOD":                    "Host report refresh service period",
	"VCSS_REFRESH_PERIOD":                    "VCenter refresh service perion ",
	"FVS_NUMBER_OF_VERIFIERS":                "NUmber of Flavor verification verifier threads",
	"FVS_NUMBER_OF_DATA_FETCHERS":            "Number of Flavor verification data fetcher threads",
	"FVS_SKIP_FLAVOR_SIGNATURE_VERIFICATION": "Skips flavor signature verification when set to true",
	"SERVER_PORT":                            "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":                    "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT":             "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":                   "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":                    "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":                "Max Length Of Request Header in Bytes ",
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_config:Run() Entering")
	defer log.Trace("tasks/update_config:Run() Leaving")
	if uc.ServiceConfig.Username == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_USERNAME is not set")
	}
	if uc.ServiceConfig.Password == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_PASSWORD is not set")
	}
	if uc.AASApiUrl == "" {
		return errors.New("HVS configuration not provided: AAS_BASE_URL is not set")
	}
	(*uc.AppConfig).AASApiUrl = uc.AASApiUrl
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt("log-max-length"),
		EnableStdout: viper.GetBool("log-enable-stdout"),
		Level:        viper.GetString("log-level"),
	}

	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 {
		uc.ServerConfig.Port = uc.DefaultPort
	}
	(*uc.AppConfig).Server = uc.ServerConfig
	(*uc.AppConfig).HVS = uc.ServiceConfig
	(*uc.AppConfig).HRRS = hrrs.HRRSConfig{
		RefreshPeriod: viper.GetDuration(constants.HrrsRefreshPeriod),
	}
	(*uc.AppConfig).VCSS = config.VCSSConfig{
		RefreshPeriod: viper.GetDuration(constants.VcssRefreshPeriod),
	}
	(*uc.AppConfig).FVS = config.FVSConfig{
		NumberOfVerifiers:               viper.GetInt(constants.FvsNumberOfVerifiers),
		NumberOfDataFetchers:            viper.GetInt(constants.FvsNumberOfDataFetchers),
		SkipFlavorSignatureVerification: viper.GetBool(constants.FvsSkipFlavorSignatureVerification),
	}

	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	if (*uc.AppConfig).HVS.Username == "" {
		return errors.New("HVS username is not set in the configuration")
	}
	if (*uc.AppConfig).HVS.Password == "" {
		return errors.New("HVS password is not set in the configuration")
	}
	if (*uc.AppConfig).AASApiUrl == "" {
		return errors.New("AAS API url is not set in the configuration")
	}
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
