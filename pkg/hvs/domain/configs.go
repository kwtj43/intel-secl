/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package domain

import (
	"github.com/golang/groupcache/lru"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
)

type HostTrustVerifierConfig struct {
	FlavorStore                     FlavorStore
	FlavorGroupStore                FlavorGroupStore
	HostStore                       HostStore
	ReportStore                     ReportStore
	FlavorVerifier                  verifier.Verifier
	CertsStore                      models.CertificatesStore
	SamlIssuerConfig                saml.IssuerConfiguration
	SkipFlavorSignatureVerification bool
	HostTrustCache                  *lru.Cache
}

type HostTrustMgrConfig struct {
	PersistStore      QueueStore
	HostStore         HostStore
	HostStatusStore   HostStatusStore
	HostFetcher       HostDataFetcher
	Verifiers         int
	HostTrustVerifier HostTrustVerifier
}

type HostDataFetcherConfig struct {
	HostConnectorProvider host_connector.HostConnectorProvider
	HostConnectionConfig  HostConnectionConfig
	RetryTimeMinutes      int
	HostStatusStore       HostStatusStore
	HostStore             HostStore
	HostTrustCache        *lru.Cache
}

type HostControllerConfig struct {
	HostConnectorProvider host_connector.HostConnectorProvider
	DataEncryptionKey     []byte
	Username              string
	Password              string
}

type TagCertControllerConfig struct {
	AASApiUrl       string
	ServiceUsername string
	ServicePassword string
}

type HostConnectionConfig struct {
	HCStore         HostCredentialStore
	ServiceUsername string
	ServicePassword string
}
