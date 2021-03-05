/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

type HardwareFeature struct {
	Enabled bool `json:"enabled,string"`
}

type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		//		MSR     string `json:"msr"`
	} `json:"meta"`
}

type TPM struct {
	HardwareFeature
	Meta struct {
		TPMVersion string `json:"tpm_version"`
		PCRBanks   string `json:"pcr_banks"`
	} `json:"meta"`
}

type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled"`
	} `json:"meta"`
}

type HostInfo struct {
	OSName         string `json:"os_name"`
	OSVersion      string `json:"os_version"`
	BiosVersion    string `json:"bios_version"`
	VMMName        string `json:"vmm_name"`
	VMMVersion     string `json:"vmm_version"`
	ProcessorInfo  string `json:"processor_info"`
	HostName       string `json:"host_name"`
	BiosName       string `json:"bios_name"`
	HardwareUUID   string `json:"hardware_uuid"`
	ProcessorFlags string `json:"process_flags"`
	//NumberOfSockets     int              `json:"no_of_sockets,string"`
	TbootInstalled      bool             `json:"tboot_installed,string"`
	IsDockerEnvironment bool             `json:"is_docker_env,string"`
	HardwareFeatures    HardwareFeatures `json:"hardware_features"`
	InstalledComponents []string         `json:"installed_components"`
}

type HardwareFeatures struct {
	TXT  HardwareFeature `json:"TXT"`
	TPM  TPM             `json:"TPM"`
	CBNT CBNT            `json:"CBNT"`
	UEFI UEFI            `json:"UEFI"`
	PFR  HardwareFeature `json:"PFR"`
	BMC  HardwareFeature `json:"BMC"`
}
