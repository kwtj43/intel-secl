/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"time"
)

const (
	HomeDir       = "/opt/authservice/"
	ConfigDir     = "/etc/authservice/"
	ExecutableDir = "/opt/authservice/bin/"
	ExecLinkPath  = "/usr/bin/authservice"
	RunDirPath    = "/run/authservice"

	LogDir = "/var/log/authservice/"

	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"

	TokenSignKeysAndCertDir = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile        = TokenSignKeysAndCertDir + "jwt.key"
	TokenSignCertFile       = TokenSignKeysAndCertDir + "jwtsigncert.pem"

	TrustedCAsStoreDir = ConfigDir + "certs/trustedca/"
	PIDFile            = "authservice.pid"
	ServiceRemoveCmd   = "systemctl disable authservice"
	HashingAlgorithm   = crypto.SHA384

	ServiceCommand                 = "authservice"
	ServiceName                    = "AAS"
	ExplicitServiceName            = "Authentication and Authorization Service"
	ApiVersion                     = "v1"
	ServiceUserName                = "aas"
	DefaultPort                    = 8444
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyLength               = 3072
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasJwtDurationMins      = 120
	DefaultJwtValidateCacheKeyMins = 60
	DefaultLogEntryMaxLength       = 1500
)

const (
	DefaultDBVendor            = "postgres"
	DefaultDBName              = "aas_db"
	DefaultDbConnRetryAttempts = 4
	DefaultDbConnRetryTime     = 1
	DefaultSSLCertFilePath     = ConfigDir + "aasdbcert.pem"

	//Postgres connection SslModes
	SslModeAllow      = "allow"
	SslModePrefer     = "prefer"
	SslModeVerifyCa   = "verify-ca"
	SslModeRequire    = "require"
	SslModeVerifyFull = "verify-full"

	DBTypePostgres = "postgres"
)

const (
	DefaultAasTlsSan   = "127.0.0.1,localhost"
	DefaultAasTlsCn    = "AAS TLS Certificate"
	DefaultTLSCertFile = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile  = ConfigDir + "tls.key"
)

const (
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
)

const (
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

var DefaultRoles = [4]string{Administrator, RoleManager, UserManager, UserRoleManager}

const (
	Administrator   = "Administrator"
	RoleManager     = "RoleManager"
	UserManager     = "UserManager"
	UserRoleManager = "UserRoleManager"
)

func GetDefaultAdministratorRoles() []ct.RoleCreate {

	return []ct.RoleCreate{
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    Administrator,
				Context: "",
			},
			Permissions: []string{
				"*:*:*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    RoleManager,
				Context: "",
			},
			Permissions: []string{
				RoleCreate + ":*", RoleRetrieve + ":*", RoleSearch + ":*", RoleDelete + ":*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    UserManager,
				Context: "",
			},
			Permissions: []string{
				UserCreate + ":*", UserRetrieve + ":*", UserStore + ":*", UserSearch + ":*", UserDelete + ":*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    UserRoleManager,
				Context: "",
			},
			Permissions: []string{
				UserRoleCreate + ":*", UserRoleRetrieve + ":*", UserRoleSearch + ":*", UserRoleDelete + ":*",
			},
		},
	}
}
