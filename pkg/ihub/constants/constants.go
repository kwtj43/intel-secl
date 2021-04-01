/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	ServiceName                 = "ihub"
	ExplicitServiceName         = "Integration Hub"
	PollingIntervalMinutes      = 2
	HomeDir                     = "/opt/ihub/"
	ConfigDir                   = "/etc/ihub/"
	DefaultConfigFilePath       = ConfigDir + "config.yml"
	ExecLinkPath                = "/usr/bin/ihub"
	RunDirPath                  = "/run/ihub"
	LogDir                      = "/var/log/ihub/"
	ConfigFile                  = "config"
	DefaultTLSCertFile          = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile           = ConfigDir + "tls-key.pem"
	PublickeyLocation           = ConfigDir + "ihub_public_key.pem"
	PrivatekeyLocation          = ConfigDir + "ihub_private_key.pem"
	TrustedCAsStoreDir          = ConfigDir + "certs/trustedca/"
	SamlCertFilePath            = ConfigDir + "certs/saml/saml-cert.pem"
	ServiceRemoveCmd            = "systemctl disable ihub"
	DefaultKeyAlgorithm         = "rsa"
	DefaultKeyLength            = 3072
	DefaultTLSSan               = "127.0.0.1,localhost"
	DefaultIHUBTlsCn            = "Integration Hub TLS Certificate"
	DefaultEndPointType         = "KUBERNETES"
	K8sTenant                   = "KUBERNETES"
	OpenStackTenant             = "OPENSTACK"
	HTTP                        = "HTTP"
	OpenStackAuthenticationAPI  = "v3/auth/tokens"
	KubernetesNodesAPI          = "api/v1/nodes"
	KubernetesCRDAPI            = "apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/"
	KubernetesCRDAPIVersion     = "crd.isecl.intel.com/v1beta1"
	KubernetesCRDKind           = "HostAttributesCrd"
	KubernetesMetaDataNameSpace = "default"
	KubernetesCRDName           = "custom-isecl"
	DefaultAttestationType      = "HVS"
	AttestationTypeSGX          = "SGX"
	DefaultK8SCertFile          = ConfigDir + "apiserver.crt"
	RegexNonStandardChar        = "[^a-zA-Z0-9]"
	DefaultLogEntryMaxlength    = 1500
	IseclTraitPrefix            = "CUSTOM_ISECL"
	TraitAssetTagPrefix         = "_AT_"
	TraitHardwareFeaturesPrefix = "_HAS_"
	TraitDelimiter              = "_"
	TrustedTrait                = IseclTraitPrefix + TraitDelimiter + "TRUSTED"
	OpenStackAPIVersion         = "placement 1.23"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

const (
	/*Open Stack Specific Constants */
	SgxTraitPrefix              = "SGX_"
	SgxTraitEnabled             = SgxTraitPrefix + "ENABLED"
	SgxTraitSupported           = SgxTraitPrefix + "SUPPORTED"
	SgxTraitTcbUpToDate         = SgxTraitPrefix + "TCBUPTODATE"
	SgxTraitEpcSize             = SgxTraitPrefix + "EPC_SIZE"
	SgxTraitEpcSizeNotAvailable = "UNAVAILABLE"
	SgxTraitFlcEnabled          = SgxTraitPrefix + "FLC_ENABLED"
	RegexEpcSize                = `[[:digit:]]+(\.[[:digit:]]+)? [KMGT]?B`
)
