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

func testOsInfoParser(t *testing.T, expectedResults *model.HostInfo) {
	hostInfo := model.HostInfo{}
	osInfoParser := osInfoParser{}
	osInfoParser.Init()

	err := osInfoParser.Parse(&hostInfo)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&hostInfo, expectedResults) {
		t.Errorf("The parsed OS data does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults, hostInfo)
	}
}

func TestOsInfoPurley(t *testing.T) {
	osReleaseFile = "test_data/purley/os-release"

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "Red Hat Enterprise Linux"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &expectedResults)
}

func TestOsInfoWhitley(t *testing.T) {
	osReleaseFile = "test_data/whitley/os-release"

	expectedResults := model.HostInfo{}
	expectedResults.OSName = "Red Hat Enterprise Linux"
	expectedResults.OSVersion = "8.1"

	testOsInfoParser(t, &expectedResults)
}
