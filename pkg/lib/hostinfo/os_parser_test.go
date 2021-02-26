/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"testing"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

func testOsInfoParser(t *testing.T) {
	hostInfo := model.HostInfo{}
	osInfoParser := osInfoParser{}
	osInfoParser.Init()

	err := osInfoParser.Parse(&hostInfo)
	if err != nil {
		t.Error(err)
	}

	if hostInfo.OSName != "Red Hat Enterprise Linux" {
		t.Errorf("Expected OSName 'Red Hat Enterprise Linux' but got '%s'", hostInfo.OSName)
	}

	if hostInfo.OSVersion != "8.1" {
		t.Errorf("Expected OSVersion '8.1' but got '%s'", hostInfo.OSVersion)
	}
}

func TestOsInfoPurley(t *testing.T) {
	osReleaseFile = "test_data/purley/os-release"
	testOsInfoParser(t)
}

func TestOsInfoWhitley(t *testing.T) {
	osReleaseFile = "test_data/whitley/os-release"
	testOsInfoParser(t)
}
