/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

// go build -ldflags "-X intel-secl/hostinfo.smbiosFile=/tmp/dmi.bin" main.go

var (
	smbiosFile    = "/sys/firmware/dmi/tables/DMI"
	osReleaseFile = "/etc/os-release"
	msrFile       = "/dev/cpu/0/msr"
	tpm2AcpiFile  = "/sys/firmware/acpi/tables/TPM2"
	hostNameFile  = "/etc/hostname"
	isDockerFile  = "/.dockerenv"
	tpmDeviceFile = "/dev/tpm0"
)
