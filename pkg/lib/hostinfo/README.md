# Hostinfo

The `hostinfo` package is used to create a 'HostInfo' structure (see /intel-secl/pkg/model/ta) on the current Linux host.  It uses a variety of data sources including SMBIOS/ACPI tables, /dev/cpu, etc. as documented in the `Field Descriptions` table below.

## Example Go Usage
```
hostInfoParser, _ := hostinfo.NewHostInfoParser()
hostInfo, _ := hostInfoParser.Parse()
```

## Field Descriptions
|Field|Description|Data Source|
|-----|-----------|-----------|
|OSName|The name of the OS (ex. “RedHatEnterprise”).|Parsed from /etc/os-release.|
|OSVersion|The version of the OS/distribution (ex. "8.1", not kernel version).|Parsed from /etc/os-release.|
|BiosVersion|The version string of the Bios.|Parsed from SMBIOS table type #0.|
|BiosName|The vendor of the Bios (ex. "Intel Corporation").|Parsed from SMBIOS table type #0.|
|VMMName|Returns “docker” or “virsh” if installed (otherwise empty).||
|VMMVersion|Returns the version of docker/virsh when installed (otherwise empty).||
|ProcessorInfo|The processor id.|Parsed from SMBIOS table type #4.|
|ProcssorFlags|The processor flags.|Parsed from SMBIOS table type #4.|
|HostName|Host name.|Parsed from /etc/hostname.|
|HardwareUUID|Unique hardware id.|Parsed from SMBIOS table type #1.|
|NumberOfSockets|Number of CPUs.||
|TbootInstalled|True when tboot is installed.||
|IsDockerEnvironment|True when the Trust-Agent is running in a container.||
|HardwareFeatures.TXT.Enabled||Parsed from /dev/cpu/0/msr.|
|HardwareFeatures.TPM.Enabled|True when a TPM is present in the platform.||
|HardwareFeatures.TPM.Meta.TPMVersion|Version of the TPM.  '1.2' or '2.0'.||
|HardwareFeatures.TPM.Meta.PCRBanks|REMOVED in v3.4||
|HardwareFeatures.CBNT.Enabled|True when BootGuard is present.|Parsed from /dev/cpu/0/msr.|
|HardwareFeatures.CBNT.Meta.Profile|The BootGuard profile.  ("BTG0", "BTG3", "BTG4" or "BTG5")||
|HardwareFeatures.CBNT.Meta.MSR|REMOVE???||
|HardwareFeatures.UEFI.Enabled|True when the Bios is EFI (not legacy bios).||
|HardwareFeatures.UEFI.Meta.SecureBootEnabled|True when secure-boot is enabled.||
|Installed Components|Always contains 'tagent' (Trust-Agent), also contains 'wlagent' when installed.||