/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"crypto/x509/pkix"
	"fmt"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/tasks"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (app *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, flag := range args {
		if flag == "--force" {
			force = true
		}
		if flag == "-f" || flag == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := app.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(app.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(app.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
				}
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(app.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(app.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = app.Config.SaveConfiguration(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// Containers are always run as non root users, does not require changing ownership of config directories
	if _, err := os.Stat("/.container-env"); err == nil {
		return nil
	}

	return cos.ChownDirForUser(constants.ServiceName, app.configDir())
}

// a helper function for setting up the task runner
func (app *App) setupTaskRunner() (*setup.Runner, error) {
	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if app.configuration() == nil {
		app.Config = defaultConfig()
	}

	runner := setup.NewRunner()
	runner.ConsoleWriter = app.consoleWriter()
	runner.ErrorWriter = app.errorWriter()

	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: app.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		TlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
	})

	runner.AddTask("download-cert-tls", "tls", &setup.DownloadCert{
		KeyFile:      viper.GetString("tls-key-file"),
		CertFile:     viper.GetString("tls-cert-file"),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString("tls-common-name"),
		},
		SanList:       viper.GetString("tls-san-list"),
		CertType:      "tls",
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: app.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	})

	runner.AddTask("attestation-service-connection", "", &tasks.AttestationServiceConnection{
		AttestationConfig: &app.Config.AttestationService,
		ConsoleWriter:     app.consoleWriter(),
	})

	runner.AddTask("tenant-service-connection", "", &tasks.TenantConnection{
		TenantConfig:  &app.Config.Endpoint,
		ConsoleWriter: app.consoleWriter(),
	})

	runner.AddTask("create-signing-key", "", &tasks.CreateSigningKey{
		PrivateKeyLocation: constants.PrivatekeyLocation,
		PublicKeyLocation:  constants.PublickeyLocation,
		KeyAlgorithmLength: constants.DefaultKeyLength,
	})

	runner.AddTask("download-saml-cert", "", &tasks.DownloadSamlCert{
		AttestationConfig: &app.Config.AttestationService,
		SamlCertPath:      constants.SamlCertFilePath,
		ConsoleWriter:     app.consoleWriter(),
	})

	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ConsoleWriter: app.consoleWriter(),
		ServiceConfig: commConfig.ServiceConfig{
			Username: viper.GetString("ihub-service-username"),
			Password: viper.GetString("ihub-service-password"),
		},
		AASApiUrl: viper.GetString("aas-base-url"),
		AppConfig: &app.Config,
	})

	return runner, nil
}
