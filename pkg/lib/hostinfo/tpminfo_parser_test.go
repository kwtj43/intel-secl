/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"reflect"
	"testing"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

func testTpm2Info(t *testing.T, expectedResults *model.HostInfo) {

	hostInfo := model.HostInfo{}

	tpmInfoParser := tpmInfoParser{}
	tpmInfoParser.Init()

	err := tpmInfoParser.Parse(&hostInfo)
	if err != nil {
		t.Errorf("Failed to parse TPM2: %v", err)
	}

	if !reflect.DeepEqual(hostInfo.HardwareFeatures.TPM, expectedResults.HardwareFeatures.TPM) {
		t.Errorf("The parsed TPM data does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults.HardwareFeatures.TPM, hostInfo.HardwareFeatures.TPM)
	}
}

func TestTpm2Purley(t *testing.T) {
	tpm2AcpiFile = "test_data/purley/TPM2"
	tpmDeviceFile = "test_data/Readme.md" // for testing, just point to a valid file so the parser defines "TPM.Supported"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.TPM.Supported = true
	expectedResults.HardwareFeatures.TPM.Enabled = true
	expectedResults.HardwareFeatures.TPM.Meta.TPMVersion = constTpm20
	expectedResults.HardwareFeatures.TPM.Meta.PCRBanks = constPcrBanks

	testTpm2Info(t, &expectedResults)
}

func TestTpm2Whitley(t *testing.T) {
	tpm2AcpiFile = "test_data/whitley/TPM2"
	tpmDeviceFile = "test_data/Readme.md" // for testing, just point to a valid file so the parser defines "TPM.Supported"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.TPM.Supported = true
	expectedResults.HardwareFeatures.TPM.Enabled = true
	expectedResults.HardwareFeatures.TPM.Meta.TPMVersion = constTpm20
	expectedResults.HardwareFeatures.TPM.Meta.PCRBanks = constPcrBanks

	testTpm2Info(t, &expectedResults)
}

func TestTpm2NoAcpiFile(t *testing.T) {
	tpm2AcpiFile = "file does not exists"
	tpmDeviceFile = "test_data/Readme.md" // for testing, just point to a valid file so the parser defines "TPM.Supported"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.TPM.Supported = true
	expectedResults.HardwareFeatures.TPM.Enabled = false

	testTpm2Info(t, &expectedResults)
}

func TestTpm2EvilMagic(t *testing.T) {
	tpm2AcpiFile = "test_data/misc/TPM2AcpiEvilMagic"
	tpmDeviceFile = "/dev/tpm0"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.TPM.Supported = false
	expectedResults.HardwareFeatures.TPM.Enabled = false

	testTpm2Info(t, &expectedResults)
}

func TestTpm2ShortFile(t *testing.T) {
	tpm2AcpiFile = "test_data/misc/TPM2AcpiShortFile"
	tpmDeviceFile = "test_data/Readme.md" // for testing, just point to a valid file so the parser defines "TPM.Supported"

	expectedResults := model.HostInfo{}
	expectedResults.HardwareFeatures.TPM.Supported = true
	expectedResults.HardwareFeatures.TPM.Enabled = false

	testTpm2Info(t, &expectedResults)
}
