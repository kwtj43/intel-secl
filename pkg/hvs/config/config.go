/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	log "github.com/sirupsen/logrus"
	"os"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	AASApiUrl        string `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CMSBaseURL       string `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`

	HVS      commConfig.ServiceConfig `yaml:"hvs" mapstructure:"hvs"`
	AuditLog AuditLogConfig           `yaml:"audit-log" mapstructure:"audit-log"`

	TLS           commConfig.TLSCertConfig     `yaml:"tls" mapstructure:"tls"`
	SAML          SAMLConfig                   `yaml:"saml" mapstructure:"saml"`
	FlavorSigning commConfig.SigningCertConfig `yaml:"flavor-signing" mapstructure:"flavor-signing"`

	PrivacyCA     commConfig.SelfSignedCertConfig `yaml:"privacy-ca" mapstructure:"privacy-ca"`
	EndorsementCA commConfig.SelfSignedCertConfig `yaml:"endorsement-ca" mapstructure:"endorsement-ca"`
	TagCA         commConfig.SelfSignedCertConfig `yaml:"tag-ca" mapstructure:"tag-ca"`

	Dek             string `yaml:"data-encryption-key" mapstructure:"data-encryption-key"`
	AikCertValidity int    `yaml:"aik-certificate-validity-years" mapstructure:"aik-certificate-validity-years"`

	Server commConfig.ServerConfig `yaml:"server" mapstructure:"server"`
	Log    commConfig.LogConfig    `yaml:"log" mapstructure:"log"`
	DB     commConfig.DBConfig     `yaml:"db" mapstructure:"db"`
	HRRS   hrrs.HRRSConfig         `yaml:"hrrs" mapstructure:"hrrs"`
	FVS    FVSConfig               `yaml:"fvs" mapstructure:"fvs"`
	VCSS   VCSSConfig              `yaml:"vcss" mapstructure:"vcss"`
}

type FVSConfig struct {
	NumberOfVerifiers               int  `yaml:"number-of-verifiers" mapstructure:"number-of-verifiers"`
	NumberOfDataFetchers            int  `yaml:"number-of-data-fetchers" mapstructure:"number-of-data-fetchers"`
	SkipFlavorSignatureVerification bool `yaml:"skip-flavor-signature-verification" mapstructure:"skip-flavor-signature-verification"`
	HostTrustCacheThreshold         int  `yaml:"host-trust-cache-threshold" mapstructure:"host-trust-cache-threshold"`
}

type SAMLConfig struct {
	CommonConfig    commConfig.SigningCertConfig `yaml:"common" mapstructure:"common"`
	Issuer          string                       `yaml:"issuer" mapstructure:"issuer"`
	ValiditySeconds int                          `yaml:"validity-seconds" mapstructure:"validity-seconds"`
}

type AuditLogConfig struct {
	MaxRowCount int `yaml:"max-row-count" mapstructure:"max-row-count"`
	NumRotated  int `yaml:"number-rotated" mapstructure:"number-rotated"`
	BufferSize  int `yaml:"buffer-size" mapstructure:"buffer-size"`
}

type VCSSConfig struct {
	// RefreshPeriod determines how frequently the VCSS checks the vCenter cluster for updated hosts
	RefreshPeriod time.Duration `yaml:"refresh-period" mapstructure:"refresh-period"`
}

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

// config is application specific
func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}

func (c *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing config file")
		}
	}()

	err = yaml.NewEncoder(configFile).Encode(c)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}
