/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/tasks"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {

		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		}
		if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				return errors.Wrap(err, "Error writing to console")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Error writing to console")
			}
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(a.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(a.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					return errors.Wrap(err, "Error writing to console")
				}
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(a.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Error writing to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}
	err = a.Config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Error saving config")
	}
	// Containers are always run as non root users, does not require changing ownership of config directories
	if _, err := os.Stat("/.container-env"); err == nil {
		return nil
	}

	return cos.ChownDirForUser(constants.ServiceUserName, a.configDir())
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*setup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if a.configuration() == nil {
		a.Config = defaultConfig()
	}
	if err := a.configureLogs(false, true); err != nil {
		return nil, err
	}
	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask("root-ca", "", &tasks.RootCa{
		ConsoleWriter:   a.consoleWriter(),
		CACertConfigPtr: &a.Config.CACert,
		CACertConfig: config.CACertConfig{
			Validity:     viper.GetInt("cms-ca-cert-validity"),
			Organization: viper.GetString("cms-ca-organization"),
			Locality:     viper.GetString("cms-ca-locality"),
			Province:     viper.GetString("cms-ca-province"),
			Country:      viper.GetString("cms-ca-country"),
		},
	})
	runner.AddTask("intermediate-ca", "", &tasks.IntermediateCa{
		ConsoleWriter: a.consoleWriter(),
		Config:        &a.Config.CACert,
	})
	runner.AddTask("tls", "", &tasks.TLS{
		ConsoleWriter:    a.consoleWriter(),
		TLSCertDigestPtr: &a.Config.TlsCertDigest,
		TLSSanList:       a.Config.TlsSanList,
	})
	runner.AddTask("cms-auth-token", "", &tasks.CmsAuthToken{
		ConsoleWriter: a.consoleWriter(),
		AasTlsCn:      a.Config.AasTlsCn,
		AasJwtCn:      a.Config.AasJwtCn,
		AasTlsSan:     a.Config.AasTlsSan,
		TokenDuration: a.Config.TokenDurationMins,
	})
	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ConsoleWriter: a.consoleWriter(),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		DefaultPort: constants.DefaultPort,
		AASApiUrl:   viper.GetString("aas-base-url"),
		AppConfig:   &a.Config,
	})

	return runner, nil
}
