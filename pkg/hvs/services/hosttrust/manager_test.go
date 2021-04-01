/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hostfetcher "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/host-fetcher"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/mocks"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	libVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/stretchr/testify/assert"

	"testing"
)

var (
	qs             domain.QueueStore
	hs             *mocks.MockHostStore
	hss            *mocks.MockHostStatusStore
	cfg            domain.HostDataFetcherConfig
	ht             domain.HostTrustManager
	f              domain.HostDataFetcher
	hcs            domain.HostCredentialStore
	v              domain.HostTrustVerifier
	fIds           []uuid.UUID
	service        *hosttrust.Service
	hwUuid, hostId uuid.UUID
	hostManifest   hcTypes.HostManifest
)

func SetupManagerTests() {
	qs = mocks.NewQueueStore()
	hs = mocks.NewMockHostStore()
	hss = mocks.NewMockHostStatusStore()
	hcs = mocks.NewMockHostCredentialStore()

	hwUuid = uuid.MustParse("0005AE6E-36D6-E711-906E-001560A04062")
	hostId = uuid.MustParse("204466f6-8611-4e03-934d-832172a41917")
	_, _ = hs.Create(&hvs.Host{
		HostName:         "hostname",
		Description:      "Host at test.domain.com",
		ConnectionString: "https://ta.ip.com:1443",
		HardwareUuid:     &hwUuid,
		Id:               hostId,
	})

	cfg = domain.HostDataFetcherConfig{
		HostConnectorProvider: mocks2.MockHostConnectorFactory{},
		HostConnectionConfig: domain.HostConnectionConfig{
			HCStore:         hcs,
			ServiceUsername: "serviceUsername",
			ServicePassword: "servicePassword",
		},
		RetryTimeMinutes: 7,
		HostStatusStore:  hss,
		HostStore:        hs,
		HostTrustCache:   lru.New(5),
	}

	_, f, _ = hostfetcher.NewService(cfg, 5)

	var fgIds []uuid.UUID
	//Add flavorgroup hvs_flavorgroup_test1 having flavor types platform, os and software to host
	fgIds = append(fgIds, uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"))
	//Add flavorgroup hvs_flavorgroup_test2 having flavor types host_unique to host
	fgIds = append(fgIds, uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"))
	hs.AddFlavorgroups(hostId, fgIds)

	flavorStore := mocks.NewFakeFlavorStoreWithAllFlavors("../../../lib/verifier/test_data/intel20/signed_flavors.json")
	flavorgroupStore := mocks.NewFakeFlavorgroupStore()
	flavorgroupStore.HostFlavorgroupStore = hs.HostFlavorgroupStore

	//platform flavor
	fIds = append(fIds, uuid.MustParse("b12eadd7-02da-4c9b-aed2-2252afa0260d"))
	// os flavor
	fIds = append(fIds, uuid.MustParse("49705d53-a75e-414e-998e-049cbb2a0ee6"))
	// software flavor
	fIds = append(fIds, uuid.MustParse("7f0683c1-a038-4ed4-8b29-286410f2e753"))
	// flavor group with software and platform
	flavorgroupStore.AddFlavors(uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"), fIds)

	fIds = make([]uuid.UUID, 1)
	// host_unique flavor
	fIds = append(fIds, uuid.MustParse("9a314548-5b36-479f-8158-463593e87193"))
	//Add host_unique flavor to host_unique flavorgroup
	flavorgroupStore.AddFlavors(uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"), fIds)
	flavorStore.FlavorgroupStore = flavorgroupStore.FlavorgroupStore
	flavorStore.FlavorFlavorGroupStore = flavorgroupStore.FlavorgroupFlavorStore

	verifierCertificates := createVerifierCertificates(
		"../../../lib/verifier/test_data/intel20/PrivacyCA.pem",
		"../../../lib/verifier/test_data/intel20/flavor-signer.crt.pem",
		"../../../lib/verifier/test_data/intel20/cms-ca-cert.pem",
		"../../../lib/verifier/test_data/intel20/tag-cacerts.pem")

	flvrVerifier, _ := libVerifier.NewVerifier(*verifierCertificates)

	htv := domain.HostTrustVerifierConfig{
		FlavorStore:                     flavorStore,
		FlavorGroupStore:                flavorgroupStore,
		HostStore:                       hs,
		ReportStore:                     mocks.NewEmptyMockReportStore(),
		FlavorVerifier:                  flvrVerifier,
		SamlIssuerConfig:                *getIssuer(),
		SkipFlavorSignatureVerification: true,
		HostTrustCache:                  lru.New(5),
	}
	v = hosttrust.NewVerifier(htv)

	service, ht, _ = hosttrust.NewService(domain.HostTrustMgrConfig{
		PersistStore:      qs,
		HostStore:         hs,
		HostStatusStore:   hss,
		HostFetcher:       f,
		Verifiers:         5,
		HostTrustVerifier: v,
	})

	manifestJSON, _ := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	json.Unmarshal(manifestJSON, &hostManifest)
}

func TestHostTrustManagerNewService(t *testing.T) {
	SetupManagerTests()

	hwUuid, err := uuid.NewRandom()
	assert.NoError(t, err)

	newHost, err := hs.Create(&hvs.Host{
		HostName:         "test.domain.com",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     &hwUuid,
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id, nil)
	fmt.Println(hrec)
	assert.NoError(t, err)

	err = ht.VerifyHostsAsync([]uuid.UUID{newHost.Id}, true, false)
	assert.NoError(t, err)
	time.Sleep(time.Duration(5 * time.Second))

	qrecs, err := qs.Search(&models.QueueFilterCriteria{})
	assert.NoError(t, err)
	for _, qrec := range qrecs {
		fmt.Println(*qrec)
	}
}

func TestVerifier_Verify_UntrustedHost(t *testing.T) {
	SetupManagerTests()
	report, err := v.Verify(hostId, &hostManifest, false, false)
	assert.NoError(t, err)
	fmt.Println(report.TrustReport.Trusted)
	assert.Equal(t, report.TrustReport.Trusted, false)
	fmt.Println(report.Saml)
	assert.NoError(t, err)
}

func TestHostTrustManagerShutdown(t *testing.T) {
	SetupManagerTests()
	hwUuid, err := uuid.NewRandom()
	assert.NoError(t, err)

	newHost, err := hs.Create(&hvs.Host{
		HostName:         "test.domain.com",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     &hwUuid,
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id, nil)
	fmt.Println(hrec)
	assert.NoError(t, err)

	// load up a large number of hosts and check if the shutdown is processed
	// when the signal is received
	assert.NoError(t, ht.VerifyHostsAsync([]uuid.UUID{hwUuid}, true, false), "Async calls pre-shutdown should not return error")

	// call shutdown signal
	err = service.Shutdown()
	assert.NoError(t, err)

	// check if the service has been shutdown
	assert.Error(t, ht.VerifyHostsAsync([]uuid.UUID{hwUuid}, true, false), "Service post shutdown should return error")
}

func TestManager_VerifyHostSyncWithHostDataFetch(t *testing.T) {
	SetupManagerTests()

	_, err := service.VerifyHost(hostId, true, false)
	assert.NoError(t, err, "VerifyHost should not return an error when HostData is fetched")
}

func TestManager_VerifyHostSyncWithoutHostDataFetch(t *testing.T) {
	SetupManagerTests()
	_, err := service.VerifyHost(hostId, false, false)
	assert.Error(t, err, "VerifyHost should error out when the Host manifest is not present in HostStatus")
}

func TestManager_VerifyHostAsync(t *testing.T) {
	SetupManagerTests()
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, true, false),
		"VerifyHostAsync should not return an error")
}

func TestManager_VerifyQueueLogic(t *testing.T) {
	SetupManagerTests()

	for i := 0; i < 100; i++ {
		go assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, true, false),
			"VerifyHostAsync should not return an error")
		go assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, false, false),
			"VerifyHostAsync should not return an error")
	}

	// queue length should not be greater than 0
	assert.NoError(t, service.ProcessQueue(), "Process Queue should be empty")
}

func TestManager_VerifyNonExistentHost(t *testing.T) {
	SetupManagerTests()
	hostCred := &models.HostCredential{
		HostName:   "hostname",
		Credential: "https://ta.ip.com:1443",
		CreatedTs:  time.Now(),
	}
	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	hostCred.Id = newUuid
	newUuid, err = uuid.NewRandom()
	assert.NoError(t, err)
	hostCred.HostId = newUuid
	// add entries to HostCredentialStore
	hcs.Create(hostCred)

	newId, err := uuid.NewRandom()
	assert.NoError(t, err)
	_, err = service.VerifyHost(newId, true, false)
	assert.Error(t, err, "VerifyHost should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	_, err = service.VerifyHost(newId, false, false)
	assert.Error(t, err, "VerifyHost should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{newId}, true, false), "VerifyHostVerifyHostsAsync should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{newId}, false, false), "VerifyHostsAsync should error out when the Host does not exist")
}
