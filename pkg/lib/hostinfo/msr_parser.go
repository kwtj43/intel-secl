/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"encoding/binary"
	"fmt"
	"os"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

const (
	cbntMsrOffset     = 0x13A
	cbntProfile3Flags = 0x6d
	cbntProfile4Flags = 0x51
	cbntProfile5Flags = 0x7d
	cbntProfile3      = "BTGP3"
	cbntProfile4      = "BTGP4"
	cbntProfile5      = "BTGP5"
	txtMsrOffset      = 0x3A
	txtEnabledBits    = 0x3
)

// msrReader is an internal interfaces that supports unit tests
// abilty to mock data found in /dev/cpu/0/msr.
type msrReader interface {
	ReadAt(offset int64) (uint64, error)
}

type msrInfoParser struct {
	msrReader msrReader
}

func (msrInfoParser *msrInfoParser) Init() error {

	if _, err := os.Stat(msrFile); os.IsNotExist(err) {
		return fmt.Errorf("Could not find MSR file '%s'", msrFile)
	}

	msrInfoParser.msrReader = &msrReaderImpl{}

	return nil
}

func (msrInfoParser *msrInfoParser) Parse(hostInfo *model.HostInfo) error {

	err := msrInfoParser.parseTxt(hostInfo)
	if err != nil {
		return fmt.Errorf("Failed to parse TXT: %w", err)
	}

	err = msrInfoParser.parseCbnt(hostInfo)
	if err != nil {
		return fmt.Errorf("Failed to parse CBNT: %w", err)
	}

	return nil
}

func (msrInfoParser *msrInfoParser) parseTxt(hostInfo *model.HostInfo) error {

	// TODO:  hostInfo.HardwareFeatures.TXT.Present = hostInfo.ProcessFlags.Contains("SMX")

	txtFlags, err := msrInfoParser.msrReader.ReadAt(txtMsrOffset)
	if err != nil {
		return fmt.Errorf("Failed to read TXT MSR flags: %w", err)
	}

	bits, err := bitShift(txtFlags, 1, 0)
	if err != nil {
		return fmt.Errorf("Failed to extract TXT enabled bits: %w", err)
	}

	hostInfo.HardwareFeatures.TXT.Enabled = (bits == txtEnabledBits)
	return nil
}

func (msrInfoParser *msrInfoParser) parseCbnt(hostInfo *model.HostInfo) error {
	// TODO:  hostInfo.HardwareFeatures.CBNT.Present ?

	cbntFlags, err := msrInfoParser.msrReader.ReadAt(cbntMsrOffset)
	if err != nil {
		return fmt.Errorf("Failed to read CBNT MSR flags: %w", err)
	}

	enabledBits, err := bitShift(cbntFlags, 32, 32)
	if err != nil {
		return fmt.Errorf("Failed to extract CBNT enabled flags: %w", err)
	}

	hostInfo.HardwareFeatures.CBNT.Enabled = (enabledBits == 1)
	if hostInfo.HardwareFeatures.CBNT.Enabled == true {
		profileBits, err := bitShift(cbntFlags, 7, 0)
		if err != nil {
			return fmt.Errorf("Failed to extract CBNT profile flags: %w", err)
		}

		hostInfo.HardwareFeatures.CBNT.Meta.MSR = "mk ris kfm" // TODO: Should these be added to ProcessorFlags?  What code uses these?

		var profileString string
		if profileBits == cbntProfile3Flags {
			profileString = cbntProfile3
		} else if profileBits == cbntProfile4Flags {
			profileString = cbntProfile4
		} else if profileBits == cbntProfile5Flags {
			profileString = cbntProfile5
		} else {
			return fmt.Errorf("Unexpected CBNT profile flags %08x", profileBits)
		}

		hostInfo.HardwareFeatures.CBNT.Meta.Profile = profileString
	}

	return nil
}

//-------------------------------------------------------------------------------------------------
// Implementation of msrReader
//-------------------------------------------------------------------------------------------------
type msrReaderImpl struct {
}

// ReadAt seeks to 'offset', reads 8 bytes and returns the LittleEndian
// uint64 value.
func (msrReaderImpl *msrReaderImpl) ReadAt(offset int64) (uint64, error) {

	var results uint64

	msr, err := os.Open(msrFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to open MSR from '%s': %w", msrFile, err)
	}

	defer func() {
		err = msr.Close()
		if err != nil {
			fmt.Printf("Failed to close MSR file '%s': %s", msrFile, err.Error())
		}
	}()

	_, err = msr.Seek(offset, 0)
	if err != nil {
		return 0, fmt.Errorf("Could not seek to MSR location '%x' in file '%s'", offset, msrFile)
	}

	err = binary.Read(msr, binary.LittleEndian, &results)
	if err != nil {
		return 0, fmt.Errorf("Failed to read results from MSR file '%s': %w", msrFile, err)
	}

	//	fmt.Printf("MSR[%x]: %x\n", offset, results)

	return results, nil
}

func bitShift(value uint64, hibit uint, lowbit uint) (uint64, error) {
	bits := hibit - lowbit + 1
	if bits > 64 {
		return 0, fmt.Errorf("Invalid hi/low bit shift parameters: %x : %x", lowbit, hibit)
	}

	value >>= lowbit
	value &= (uint64(1) << bits) - 1
	return value, nil
}
