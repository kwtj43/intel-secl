/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/tasks"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
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
				return errors.Wrap(err, "Failed to write to console")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
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
					return errors.Wrap(err, "Failed to write to console")
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
				return errors.Wrap(err, "Failed to write to console")
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
	a.setupHRRSConfig()

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

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
	runner.AddTask("database", "", &tasks.DBSetup{
		DBConfigPtr:   &a.Config.DB,
		DBConfig:      dbConf,
		SSLCertSource: viper.GetString("db-ssl-cert-source"),
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("create-default-flavorgroup", "", &tasks.CreateDefaultFlavor{
		DBConfig: dbConf,
	})
	runner.AddTask("create-dek", "", &tasks.CreateDek{
		DekStore: &a.Config.Dek,
	})
	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedRootCACertsDir,
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
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	})
	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ServiceConfig: commConfig.ServiceConfig{
			Username: viper.GetString("hvs-service-username"),
			Password: viper.GetString("hvs-service-password"),
		},
		AASApiUrl: viper.GetString("aas-base-url"),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		DefaultPort:   constants.DefaultHVSListenerPort,
		AppConfig:     &a.Config,
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("download-cert-saml", "saml", a.downloadCertTask("saml"))
	runner.AddTask("download-cert-flavor-signing", "flavor-signing", a.downloadCertTask("flavor-signing"))

	runner.AddTask("create-privacy-ca", "privacy-ca", a.selfSignTask("privacy-ca"))
	runner.AddTask("create-endorsement-ca", "endorsement-ca", a.selfSignTask("endorsement-ca"))
	runner.AddTask("create-tag-ca", "tag-ca", a.selfSignTask("tag-ca"))
	runner.AddTask("create-default-flavor-template", "", &tasks.CreateDefaultFlavorTemplate{
		DBConf: dbConf,
	})

	return runner, nil
}

func (a *App) downloadCertTask(certType string) setup.Task {
	certTypeReq := certType
	var updateConfig *commConfig.SigningCertConfig
	var updateSAMLConfig *config.SAMLConfig
	switch certType {
	case "saml":
		updateConfig = &a.configuration().SAML.CommonConfig
		updateSAMLConfig = &a.configuration().SAML
		certTypeReq = "signing"
	case "flavor-signing":
		updateConfig = &a.configuration().FlavorSigning
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(certType + "-key-file")
		updateConfig.CertFile = viper.GetString(certType + "-cert-file")
		updateConfig.CommonName = viper.GetString(certType + "-common-name")
	}
	if updateSAMLConfig != nil && updateConfig != nil {
		updateSAMLConfig.CommonConfig = *updateConfig
		updateSAMLConfig.ValiditySeconds = viper.GetInt("saml-validity-seconds")
		updateSAMLConfig.Issuer = viper.GetString("saml-issuer-name")
	}
	return &setup.DownloadCert{
		KeyFile:      viper.GetString(certType + "-key-file"),
		CertFile:     viper.GetString(certType + "-cert-file"),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(certType + "-common-name"),
		},
		CertType:      certTypeReq,
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	}
}

func (a *App) selfSignTask(name string) setup.Task {
	var updateConfig *commConfig.SelfSignedCertConfig
	switch name {
	case "privacy-ca":
		updateConfig = &a.configuration().PrivacyCA
	case "endorsement-ca":
		updateConfig = &a.configuration().EndorsementCA
	case "tag-ca":
		updateConfig = &a.configuration().TagCA
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(name + "-key-file")
		updateConfig.CertFile = viper.GetString(name + "-cert-file")
		updateConfig.CommonName = viper.GetString(name + "-common-name")
		updateConfig.Issuer = viper.GetString(name + "-issuer")
		updateConfig.ValidityDays = viper.GetInt(name + "-validity-years")
	}
	return &setup.SelfSignedCert{
		CertFile:     viper.GetString(name + "-cert-file"),
		KeyFile:      viper.GetString(name + "-key-file"),
		CommonName:   viper.GetString(name + "-common-name"),
		Issuer:       viper.GetString(name + "-issuer"),
		SANList:      viper.GetString(name + "-san-list"),
		ValidityDays: viper.GetInt(name + "-validity-years"),

		ConsoleWriter: a.consoleWriter(),
	}
}

// The HRRS does not require setup, just one configuration parameter.  This function
// populates the HRRS config during 'hvs setup'.
//
// The function needs to handle...
// - The first run of setup with new a config.  The config will either have the default
//   values (from defaultConfig()) or custom values from env/answer file.
// - Setup is being re-run and the config has been previously populated (from 'new')...
//   - User has provided custom HRRS env/answer file values
//     ==> These should be applied to the config
//   - User has NOT provided custom HRRS env/answer file values
//     ==> Any previously configured custom values should be maintained
//
// This logic can achieved by just applying custom env/answer file values when they
// are different from the defaults.
func (a *App) setupHRRSConfig() {

	refreshPeriod := viper.GetDuration(constants.HrrsRefreshPeriod)
	if refreshPeriod != hrrs.DefaultRefreshPeriod {
		a.Config.HRRS.RefreshPeriod = refreshPeriod
	}
}
