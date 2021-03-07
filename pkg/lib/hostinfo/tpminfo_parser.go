/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"os"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

// tpmInfoParser uses ACPI data defined in 'tpm2AcpiFile' to determine
// if a TPM is installed and its version.
type tpmInfoParser struct{}

const (
	constPcrBanks = "SHA1_SHA256"
	constTpm20    = "2.0"
)

func (tpmInfoParser *tpmInfoParser) Init() error {
	// don't do any checking in Init -- the TPM ACPI file may does not exist,
	// which is ok and indicated a TPM is not present.
	return nil
}

func (tpmInfoParser *tpmInfoParser) Parse(hostInfo *model.HostInfo) error {

	if _, err := os.Stat(tpm2AcpiFile); os.IsNotExist(err) {
		hostInfo.HardwareFeatures.TPM.Enabled = false
		log.Debugf("'%s' file is not present, TPM is considered disabled", tpm2AcpiFile)
		return nil
	}

	file, err := os.Open(tpm2AcpiFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to open TPM ACPI file from '%s'", tpm2AcpiFile)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Errorf("Failed to close TPM2 ACPI file '%s': %v", tpm2AcpiFile, err)
		}
	}()

	magic := make([]byte, 4)
	n, err := file.Read(magic)
	if err != nil {
		return errors.Wrapf(err, "Failed to read magic from TPM ACPI file from '%s'", tpm2AcpiFile)
	}

	if n < 4 {
		log.Warnf("The TPM ACPI file '%s' is too small (%d bytes).  The TPM will be considered disabled", tpm2AcpiFile, n)
		return nil
	}

	if string(magic) == "TPM2" {
		hostInfo.HardwareFeatures.TPM.Enabled = true
		hostInfo.HardwareFeatures.TPM.Meta.TPMVersion = constTpm20

		// TODO -- remove after rebase to v3.4
		hostInfo.HardwareFeatures.TPM.Meta.PCRBanks = constPcrBanks
	}

	return nil
}
