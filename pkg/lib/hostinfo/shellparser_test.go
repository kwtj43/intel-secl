/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"reflect"
	"testing"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/mock"
)

func compareHostInfo(t *testing.T, expectedResults *model.HostInfo, actualResults *model.HostInfo) {
	if !reflect.DeepEqual(actualResults, expectedResults) {
		t.Errorf("The HostInfo actual results does not match the expected results.\nExpected: %+v\nActual: %+v\n", expectedResults, actualResults)
	}
}

func TestVMMDocker(t *testing.T) {

	expectedResults := model.HostInfo{}
	expectedResults.VMMName = constVmmNameDocker
	expectedResults.VMMVersion = "19.03.7"

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", dockerVersionCommand).Return("19.03.7", 0, nil)
	mockShellExecutor.On("Execute", virshVersionCommand).Return("", constErrorCodeNotFound, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseVmm(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

func TestVMMVirsh(t *testing.T) {

	expectedResults := model.HostInfo{}
	expectedResults.VMMName = constVmmNameVirsh
	expectedResults.VMMVersion = "4.5.0"

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", dockerVersionCommand).Return("", constErrorCodeNotFound, nil)
	mockShellExecutor.On("Execute", virshVersionCommand).Return("4.5.0\n", 0, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseVmm(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

func TestTboot(t *testing.T) {

	expectedResults := model.HostInfo{}
	expectedResults.TbootInstalled = true

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", tbootCommand).Return("some help string", 0, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseTboot(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

func TestTagentComponent(t *testing.T) {

	expectedResults := model.HostInfo{}
	expectedResults.InstalledComponents = []string{constTagentComponent}

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", tagentCommand).Return("tagent version x.y.z", 0, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseTagentComponent(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

func TestBothComponents(t *testing.T) {

	expectedResults := model.HostInfo{}
	expectedResults.InstalledComponents = []string{constTagentComponent, constWlagentComponent}

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", tagentCommand).Return("tagent version x.y.z", 0, nil)
	mockShellExecutor.On("Execute", wlagentCommand).Return("wlagent version x.y.z", 0, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseTagentComponent(&actualResults)
	shellInfoParser.parseWlagentComponent(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

func TestJustTagentComponent(t *testing.T) {

	// In many cases, the Trust-Agent is installed and Workload Agent is not...
	expectedResults := model.HostInfo{}
	expectedResults.InstalledComponents = []string{constWlagentComponent}

	mockShellExecutor := new(mockShellExecutor)
	mockShellExecutor.On("Execute", wlagentCommand).Return("wlagent version x.y.z", 0, nil)
	mockShellExecutor.On("Execute", wlagentCommand).Return("", constErrorCodeNotFound, nil)

	shellInfoParser := shellInfoParser{
		shellExecutor: mockShellExecutor,
	}

	actualResults := model.HostInfo{}
	shellInfoParser.parseWlagentComponent(&actualResults)

	compareHostInfo(t, &expectedResults, &actualResults)
}

//-------------------------------------------------------------------------------------------------
// Mock implementation of shell for unit testing
//-------------------------------------------------------------------------------------------------
type mockShellExecutor struct {
	mock.Mock
}

func (mockShellExecutor mockShellExecutor) Execute(command []string) (string, int, error) {
	args := mockShellExecutor.Called(command)
	return args.String(0), args.Int(1), args.Error(2)
}
