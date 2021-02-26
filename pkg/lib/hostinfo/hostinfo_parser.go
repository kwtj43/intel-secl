/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"fmt"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

var (
	presetOSName = ""

	infoParsers = []InfoParser{
		&smbiosInfoParser{},
		&osInfoParser{},
	}
)

// HostInfoParser collects the host's meta-data from the current
// host and returns a "HostInfo" struct (see intel-secl/v3/pkg/model/ta/HostInfo structure).
type HostInfoParser interface {
	Parse() (*model.HostInfo, error)
}

// InfoParser is an interface implmented internally to collect
// the different fields of the HostInfo structure.
type InfoParser interface {
	// Init is called on each of the 'infoParsers' during NewHostInfoProcess.
	// It allows the parser to initialize or an error.
	Init() error

	// Parse is called on each of the 'infoParsers' during HostInfoParser.Parse().
	// The InfoParse should populate the HostInfo parameter with data.
	Parse(*model.HostInfo) error
}

// NewHostInfoParser creates a new HostInfoParser.
func NewHostInfoParser() (HostInfoParser, error) {
	var err error

	// first intialize all of the info parsers to ensure there are
	// not any errors (i.e., they can run).
	for _, infoParser := range infoParsers {
		err = infoParser.Init()
		if err != nil {
			return nil, fmt.Errorf("Failed to intialize parser: %w", err)
		}
	}

	hostInfoParser := hostInfoParser{}

	return &hostInfoParser, nil
}

type hostInfoParser struct {
}

// Parse creates and populates a HostInfo structure.
func (hostInfoParser *hostInfoParser) Parse() (*model.HostInfo, error) {

	hostInfo := model.HostInfo{}
	var err error

	for _, infoParser := range infoParsers {
		err = infoParser.Parse(&hostInfo)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse host info: %w", err)
		}
	}

	return &hostInfo, nil
}
