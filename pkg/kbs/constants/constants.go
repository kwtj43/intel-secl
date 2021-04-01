/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

// general KBS constants
const (
	ServiceName         = "KBS"
	ExplicitServiceName = "Key Broker Service"
	ServiceDir          = "kbs/"
	ApiVersion          = "/v1"
	ServiceUserName     = "kbs"

	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir
	ConfigDir    = "/etc/" + ServiceDir
	ConfigFile   = "config"

	KeysDir               = HomeDir + "keys/"
	KeysTransferPolicyDir = HomeDir + "keys-transfer-policy/"

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	SamlCertsDir              = ConfigDir + "certs/saml/"
	TpmIdentityCertsDir       = ConfigDir + "certs/tpm-identity/"

	// defaults
	DefaultKeyManager         = "Directory"
	DefaultEndpointUrl        = "http://localhost"
	DefaultTransferPolicy     = "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"
	DefaultConfigFilePath     = ConfigDir + "config.yml"
	DefaultTransferPolicyFile = ConfigDir + "default_transfer_policy"

	// default locations for tls certificate and key
	DefaultTLSCertPath = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyPath  = ConfigDir + "tls.key"

	// service remove command
	ServiceRemoveCmd = "systemctl disable kbs"

	// tls constants
	DefaultKbsTlsCn     = "KBS TLS Certificate"
	DefaultKbsTlsSan    = "127.0.0.1,localhost"
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072

	// jwt constants
	JWTCertsCacheTime = "1m"

	// log constants
	DefaultLogLevel     = "info"
	DefaultLogMaxlength = 1500

	// server constants
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultKBSListenerPort   = 9443

	// keymanager constants
	DirectoryKeyManager = "directory"
	KmipKeyManager      = "kmip"

	// algorithm constants
	CRYPTOALG_AES = "AES"
	CRYPTOALG_RSA = "RSA"
	CRYPTOALG_EC  = "EC"

	// kmip constants
	KMIP_CRYPTOALG_AES  = 0x03
	KMIP_CRYPTOALG_RSA  = 0x04
	KMIP_CRYPTOALG_EC   = 0x06
	KMIP_CLIENT_SUCCESS = 0x00

	NonceLength = 32
)

///SKC Specific constants
const (
	DefaultSWLabel          = "SW"
	DefaultSGXLabel         = "SGX"
	VerifyQuote             = "/sgx_qv_verify_quote"
	KeyTransferOpertaion    = "transfer key"
	SessionOperation        = "establish session key"
	SuccessStatus           = "success"
	FailureStatus           = "failure"
	SGXAlgorithmType        = "AES256-GCM"
	SWAlgorithmType         = "AES256-WRAP"
	TransferRoleType        = "KeyTransfer"
	ContextPermissionsRegex = "^(permissions=)(.*)$"
	TCBLevelOutOfDate       = "OutOfDate"
)
