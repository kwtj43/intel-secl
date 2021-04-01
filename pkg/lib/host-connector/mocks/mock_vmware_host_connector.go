/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"github.com/intel-secl/intel-secl/v3/pkg/clients/vmware"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"github.com/vmware/govmomi/vim25/mo"
)

type MockVmwareConnector struct {
	client *vmware.MockVMWareClient
	mock.Mock
}

func (vhc *MockVmwareConnector) GetHostDetails() (taModel.HostInfo, error) {
	args := vhc.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (vhc *MockVmwareConnector) GetHostManifest([]int) (types.HostManifest, error) {
	args := vhc.Called()
	return args.Get(0).(types.HostManifest), args.Error(1)
}

func (vhc *MockVmwareConnector) DeployAssetTag(hardwareUUID, tag string) error {
	args := vhc.Called(hardwareUUID, tag)
	return args.Error(0)
}

func (vhc *MockVmwareConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	args := vhc.Called(manifest)
	return args.Error(0)
}

func (vhc *MockVmwareConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	args := vhc.Called(manifest)
	return args.Get(0).(taModel.Measurement), args.Error(1)
}

func (vhc *MockVmwareConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	args := vhc.Called(clusterName)
	return args.Get(0).([]mo.HostSystem), args.Error(1)
}
