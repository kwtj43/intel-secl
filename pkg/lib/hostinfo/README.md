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
|BiosVersion|The version string of the Bios.|Parsed from SMBIOS table type #0, "BiosVersion" field at 5h.|
|BiosName|The vendor of the Bios (ex. "Intel Corporation").|Parsed from SMBIOS table type #0, "Vendor" field at 4h.|
|VMMName|Returns “docker” or “virsh” if installed (otherwise empty).|The presence of the VMM is determined by the commands in VMMVersion.|
|VMMVersion|Returns the version of docker/virsh when installed (otherwise empty).|Docker: output of `docker --version --format='{{.Client.Version}}'`.  Virsh: `virsh -v`|
|ProcessorInfo|The processor id.|Parsed from SMBIOS table type #4, "ProcessorID" at 8h.|
|ProcssorFlags|The processor flags.|String version of "ProcessorID" (see ProcessorInfo).|
|HostName|Host name.|Parsed from /etc/hostname.|
|HardwareUUID|Unique hardware id.|Parsed from SMBIOS table type #1, "UIID" at 8h.|
|TbootInstalled|True when tboot is installed.|True when 'txt-stat -h' executes without error.|
|IsDockerEnvironment|True when the Trust-Agent is running in a container.| True when `/.dockerenv` file is present on the system.|
|HardwareFeatures.TXT.Supported||Defaults to 'true' (assuming Intel processor).|
|HardwareFeatures.TXT.Enabled||Based on /dev/cpu/0/msr bits at offset 0x3A.|
|HardwareFeatures.TPM.Supported||True when /dev/tpm0 is present.|
|HardwareFeatures.TPM.Enabled||True when /sys/firmware/acpi/tables/TPM2 is present and starts with magic "TPM2" (for Linux, TPM2.0 is required).|
|HardwareFeatures.TPM.Meta.TPMVersion|Version of the TPM (ex. "2.0").| "2.0" when /sys/firmware/acpi/tables/TPM2 is present and starts with magic "TPM2".|
|HardwareFeatures.TPM.Meta.PCRBanks||KWT: REMOVE WITH v3.5 MERGE.|
|HardwareFeatures.CBNT.Supported||True when CBNT is enabled.|
|HardwareFeatures.CBNT.Enabled|True when BootGuard is present.|Based on /dev/cpu/0/msr bits at offset 0x13A.|
|HardwareFeatures.CBNT.Meta.Profile|The BootGuard profile.  ("BTG0", "BTG3", "BTG4" or "BTG5")|Parsed from bits in /dev/cpu/0/msr at offset 0x13A.|
|HardwareFeatures.CBNT.Meta.MSR|KWT: REMOVE?|"mk ris kfm" when CBNT is present.|
|HardwareFeatures.UEFI.Supported|True when UEFI.Enabled.||
|HardwareFeatures.UEFI.Enabled|True when the Bios is EFI (not legacy bios).|Parsed from SMBIOS table type #0, "BIOS Characteristics" at Ah.|
|HardwareFeatures.UEFI.Meta.SecureBootEnabled|True when secure-boot is enabled.|KWT: Parse EFI VARs?|
|InstalledComponents|Always contains 'tagent' (Trust-Agent), also contains 'wlagent' when installed.|Values are determined if the agent executables can be run (ex. `tagent version` and `wlagent version`).|