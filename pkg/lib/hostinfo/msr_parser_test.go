/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"testing"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/mock"
)

func testMsrInfoParser(t *testing.T, mockMsrReader msrReader, expectedResults *model.HostInfo) {
	hostInfo := model.HostInfo{}

	msrInfoParser := msrInfoParser{
		msrReader: mockMsrReader,
	}

	err := msrInfoParser.Parse(&hostInfo)
	if err != nil {
		t.Errorf("Failed to parse TXT: %v", err)
	}

	if hostInfo.HardwareFeatures.TXT.Enabled != expectedResults.HardwareFeatures.TXT.Enabled {
		t.Errorf("Expected TXT enabled value '%t' but got '%t'", expectedResults.HardwareFeatures.TXT.Enabled, hostInfo.HardwareFeatures.TXT.Enabled)
	}

	if hostInfo.HardwareFeatures.CBNT.Enabled != expectedResults.HardwareFeatures.CBNT.Enabled {
		t.Errorf("Expected CBNT enabled value '%t' but got '%t'", expectedResults.HardwareFeatures.CBNT.Enabled, hostInfo.HardwareFeatures.CBNT.Enabled)
	}

	if hostInfo.HardwareFeatures.CBNT.Meta.Profile != expectedResults.HardwareFeatures.CBNT.Meta.Profile {
		t.Errorf("Expected CBNT profile value '%s' but got '%s'", expectedResults.HardwareFeatures.CBNT.Meta.Profile, hostInfo.HardwareFeatures.CBNT.Meta.Profile)
	}
}

func TestMsrPositive(t *testing.T) {

	// return values from a system with TXT enabled (i.e., from MSR offset 0x51) and
	// BTG Profile 5 (at 0x13A).  This data can be viewed in bash using 'xxd'...
	//
	// >> sudo hexdump -C -s 0x3A -n 8 /dev/cpu/0/msr
	// 0000003a  05 00 10 00 00 00 00 00                           |........|
	// 00000042
	//
	// >> sudo hexdump -C -s 0x13A -n 8 /dev/cpu/0/msr
	// 0000013a  7d 00 00 00 0f 00 00 00                           |}.......|
	// 00000142

	mockMsrReader := new(mockMsrReader)
	mockMsrReader.On("ReadAt", int64(txtMsrOffset)).Return(0x10ff07, nil)
	mockMsrReader.On("ReadAt", int64(cbntMsrOffset)).Return(0xf0000007d, nil)

	hostInfo := model.HostInfo{}
	hostInfo.HardwareFeatures.TXT.Enabled = true
	hostInfo.HardwareFeatures.CBNT.Enabled = true
	hostInfo.HardwareFeatures.CBNT.Meta.Profile = cbntProfile5

	testMsrInfoParser(t, mockMsrReader, &hostInfo)
}

func TestMsrNegative(t *testing.T) {

	// return msr data where TXT and CBNT are disabled
	mockMsrReader := new(mockMsrReader)
	mockMsrReader.On("ReadAt", int64(txtMsrOffset)).Return(0x100005, nil)
	mockMsrReader.On("ReadAt", int64(cbntMsrOffset)).Return(0x400000000, nil)

	hostInfo := model.HostInfo{}
	hostInfo.HardwareFeatures.TXT.Enabled = false
	hostInfo.HardwareFeatures.CBNT.Enabled = false
	hostInfo.HardwareFeatures.CBNT.Meta.Profile = ""

	testMsrInfoParser(t, mockMsrReader, &hostInfo)
}

//-------------------------------------------------------------------------------------------------
// Mock implementation of msrReader to support unit testing
//-------------------------------------------------------------------------------------------------
type mockMsrReader struct {
	mock.Mock
}

func (mockMsrReader mockMsrReader) ReadAt(offset int64) (uint64, error) {
	args := mockMsrReader.Called(offset)
	return uint64(args.Int(0)), args.Error(1)
}
