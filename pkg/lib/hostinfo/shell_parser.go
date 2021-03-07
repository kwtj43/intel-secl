/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

const (
	constVmmNameDocker     = "Docker"
	constVmmNameVirsh      = "Virsh"
	constErrorCodeNotFound = 127 // Linux error code when a command is not found in the path
)

var (
	dockerVersionCommand = []string{"docker", "--version", "--format='{{.Client.Version}}'"}
	virshVersionCommand  = []string{"virsh", "-v"}
	tbootCommand         = []string{"txt-stat", "--help"} // just run help to determine if the program is present
)

// shellInfoParser interacts with the linux shell to collect various fields in a HostInfo
// (ex. "vmmName").
type shellInfoParser struct {
	shellExecutor shellExecutor
}

func (shellInfoParser *shellInfoParser) Init() error {
	shellInfoParser.shellExecutor = newShellExecutor()
	return nil
}

func (shellInfoParser *shellInfoParser) Parse(hostInfo *model.HostInfo) error {

	err := shellInfoParser.parseVmm(hostInfo)
	if err != nil {
		return errors.Wrap(err, "Failed to parse VMM information.")
	}

	err = shellInfoParser.parseTboot(hostInfo)
	if err != nil {
		return errors.Wrap(err, "Failed to parse TBOOT information")
	}

	return nil
}

func (shellInfoParser *shellInfoParser) parseVmm(hostInfo *model.HostInfo) error {

	out, returnCode, err := shellInfoParser.shellExecutor.Execute(dockerVersionCommand)
	if err != nil {
		return errors.Wrapf(err, "Failed to execute '%s", dockerVersionCommand)
	}

	if returnCode == 0 {
		hostInfo.VMMName = constVmmNameDocker
		hostInfo.VMMVersion = out
		return nil
	}

	// TODO: As designed in v3.5, HostInfo can be docker or virsh (but not both)

	out, returnCode, err = shellInfoParser.shellExecutor.Execute(virshVersionCommand)
	if err != nil {
		return errors.Wrapf(err, "Failed to execute '%s'", virshVersionCommand)
	}

	if returnCode == 0 {
		hostInfo.VMMName = constVmmNameVirsh
		hostInfo.VMMVersion = strings.ReplaceAll(out, "\n", "")
	}

	return nil
}

// TODO:  Turn this into a "SoftwareFeature" {installed: false, version: 1.9.12} and
// use modprobe.
func (shellInfoParser *shellInfoParser) parseTboot(hostInfo *model.HostInfo) error {

	_, returnCode, err := shellInfoParser.shellExecutor.Execute(tbootCommand)
	if err != nil {
		return err
	}

	if returnCode == 0 {
		hostInfo.TbootInstalled = true
	}

	return nil
}

//-------------------------------------------------------------------------------------------------
// 'shell' interface that allows unit tests to be mocked
//-------------------------------------------------------------------------------------------------
type shellExecutor interface {
	// Execute returns the string value of stdout and the integer error code from the shell.  If
	// any errors occur from the result of go code (not shell execution), an error is returned, the string
	// will be emtpy and the integer value will be -1.  Otherwise, the string will be populated from
	// the shell's results and the integer will be the exit code from the shell.
	Execute(command []string) (string, int, error)
}

type exitError struct {
	errorCode int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("Command return %d", e.errorCode)
}

func newShellExecutor() shellExecutor {
	return &shellImpl{}
}

type shellImpl struct{}

func (shellImpl *shellImpl) Execute(command []string) (string, int, error) {

	cmd := exec.Command(command[0], command[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Start(); err != nil {
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return out.String(), constErrorCodeNotFound, nil
		} else {
			return "", -1, errors.Wrapf(err, "Could not start command '%s'", command)
		}
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return out.String(), status.ExitStatus(), nil
			} else {
				return out.String(), -1, errors.Wrapf(err, "Failed to retrieve wait status from command '%s'", command)
			}
		} else {
			return out.String(), -1, errors.Wrapf(err, "Failed to run command '%s'", command)
		}
	}

	return out.String(), 0, nil
}
