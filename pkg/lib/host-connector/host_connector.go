/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/vmware/govmomi/vim25/mo"
)

type HostConnector interface {
	GetHostDetails() (taModel.HostInfo, error)
	GetHostManifest(pcrList []int) (types.HostManifest, error)
	DeployAssetTag(string, string) error
	DeploySoftwareManifest(taModel.Manifest) error
	GetMeasurementFromManifest(taModel.Manifest) (taModel.Measurement, error)
	GetClusterReference(string) ([]mo.HostSystem, error)
}
