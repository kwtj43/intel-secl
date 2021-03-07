/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	commonLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

var (
	presetOSName = ""

	infoParsers = []InfoParser{
		&smbiosInfoParser{},
		&osInfoParser{},
		&msrInfoParser{}, // order matters here -- txt info needs on processor flags from smbios
		&tpmInfoParser{},
		&shellInfoParser{},
		&fileInfoParser{},
	}

	log = commonLog.GetDefaultLogger()
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
			return nil, errors.Wrap(err, "Failed to intialize parser")
		}
	}

	hostInfoParser := hostInfoParserImpl{}

	return &hostInfoParser, nil
}

//-------------------------------------------------------------------------------------------------
// HostInfoParser implementation
//-------------------------------------------------------------------------------------------------
type hostInfoParserImpl struct{}

// Parse creates and populates a HostInfo structure.
func (hostInfoParser *hostInfoParserImpl) Parse() (*model.HostInfo, error) {

	hostInfo := model.HostInfo{}
	var err error

	for _, infoParser := range infoParsers {
		err = infoParser.Parse(&hostInfo)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred in '%T' while attempting to parse hostinfo.", infoParser)
		}
	}

	return &hostInfo, nil
}
