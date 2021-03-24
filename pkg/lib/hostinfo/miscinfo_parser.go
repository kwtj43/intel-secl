/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"runtime"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

// miscInfoParser currenty collects the HostInfo's NumberOfSockets field.
type miscInfoParser struct{}

func (miscInfoParser *miscInfoParser) Init() error {
	return nil
}

func (miscInfoParser *miscInfoParser) Parse(hostInfo *model.HostInfo) error {
	hostInfo.NumberOfSockets = runtime.NumCPU()
	return nil
}
