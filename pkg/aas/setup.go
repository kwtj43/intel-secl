/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/config"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/tasks"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"os"

	"strings"
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
				defaultLog.WithError(err).Error("Failed to print help")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				defaultLog.WithError(err).Error("Failed to print help")
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
					defaultLog.WithError(err).Error("Failed to print help")
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
				defaultLog.WithError(err).Error("Failed to print help")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = a.Config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
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

	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: a.consoleWriter(),
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
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	})
	dbConf := commConfig.DBConfig{
		Vendor:   viper.GetString("db-vendor"),
		Host:     viper.GetString("db-host"),
		Port:     viper.GetInt("db-port"),
		DBName:   viper.GetString("db-name"),
		Username: viper.GetString("db-username"),
		Password: viper.GetString("db-password"),
		SSLMode:  viper.GetString("db-ssl-mode"),
		SSLCert:  viper.GetString("db-ssl-cert"),

		ConnectionRetryAttempts: viper.GetInt("db-conn-retry-attempts"),
		ConnectionRetryTime:     viper.GetInt("db-conn-retry-time"),
	}
	runner.AddTask("database", "", &tasks.Database{
		DBConfigPtr:   &a.Config.DB,
		DBConfig:      dbConf,
		SSLCertSource: viper.GetString("db-ssl-cert-source"),
		ConsoleWriter: a.consoleWriter(),
	})
	serviceConfig := config.AASConfig{
		Username: viper.GetString("aas-service-username"),
		Password: viper.GetString("aas-service-password"),
	}
	runner.AddTask("admin", "", tasks.Admin{
		ServiceConfigPtr: &a.Config.AAS,
		AASConfig:        serviceConfig,
		DatabaseFactory: func() (domain.AASDatabase, error) {
			p, err := postgres.Open(a.Config.DB.Host, a.Config.DB.Port, a.Config.DB.DBName, a.Config.DB.Username,
				a.Config.DB.Password, a.Config.DB.SSLMode, a.Config.DB.SSLCert)
			if err != nil {
				defaultLog.WithError(err).Error("Failed to open postgres connection for setup task")
				return nil, err
			}
			err = p.Migrate()
			if err != nil {
				defaultLog.WithError(err).Error("Failed to migrate database")
			}
			return p, nil
		},
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("jwt", "", &setup.DownloadCert{
		KeyFile:      constants.TokenSignKeyFile,
		CertFile:     constants.TokenSignCertFile,
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString("jwt-cert-common-name"),
		},
		CertType:      "JWT-Signing",
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
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
		AppConfig:   &a.Config,
	})

	return runner, nil
}
