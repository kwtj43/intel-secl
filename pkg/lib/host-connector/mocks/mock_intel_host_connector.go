/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

//go:generate mockgen -destination=mock_intel_host_connector.go -package=host_connector github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector MockIntelConnector

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/ta"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"github.com/vmware/govmomi/vim25/mo"
	"io/ioutil"
)

type MockIntelConnector struct {
	client *ta.MockTAClient
	mock.Mock
}

func (ihc *MockIntelConnector) GetHostDetails() (taModel.HostInfo, error) {
	args := ihc.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (ihc *MockIntelConnector) GetHostManifest([]int) (types.HostManifest, error) {
	args := ihc.Called()
	var hostManifest types.HostManifest
	// this is required for any test case that requires a good HostManifest
	manifestJSON, _ := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	err := json.Unmarshal(manifestJSON, &hostManifest)
	// handle any tests that do not consider the quality of the HostManifest
	if err != nil {
		return args.Get(0).(types.HostManifest), args.Error(1)
	} else {
		return hostManifest, nil
	}
}

func (ihc *MockIntelConnector) DeployAssetTag(hardwareUUID, tag string) error {
	args := ihc.Called(hardwareUUID, tag)
	return args.Error(0)
}

func (ihc *MockIntelConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	args := ihc.Called(manifest)
	return args.Error(0)
}

func (ihc *MockIntelConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	args := ihc.Called(manifest)
	return args.Get(0).(taModel.Measurement), args.Error(1)
}

func (ihc *MockIntelConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	args := ihc.Called(clusterName)
	return args.Get(0).([]mo.HostSystem), args.Error(1)
}
