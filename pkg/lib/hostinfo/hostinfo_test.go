package hostinfo

import (
	"testing"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

// go test github.com/intel-secl/intel-secl/v3/pkg/lib/hostinfo -v

func testSMBIOS(t *testing.T, expectedResults *model.HostInfo) {

	hostInfo := model.HostInfo{}

	smbiosReader, err := newSMBIOSReader(&hostInfo)
	if err != nil {
		t.Errorf("Could not create SMBIOS reader: %v", err)
	}

	err = smbiosReader.Read()
	if err != nil {
		t.Errorf("Failed to parse SMBIOS: %v", err)
	}

	if hostInfo.BiosName != expectedResults.BiosName {
		t.Errorf("Expected BiosName '%s' but found '%s'", expectedResults.BiosName, hostInfo.BiosName)
	}

	if hostInfo.BiosVersion != expectedResults.BiosVersion {
		t.Errorf("Expected BiosVersion '%s' but found '%s'", expectedResults.BiosVersion, hostInfo.BiosVersion)
	}

	if hostInfo.HardwareUUID != expectedResults.HardwareUUID {
		t.Errorf("Expected HardwareUUID '%s' but found '%s'", expectedResults.HardwareUUID, hostInfo.HardwareUUID)
	}

	if hostInfo.ProcessorInfo != expectedResults.ProcessorInfo {
		t.Errorf("Expected ProcessorInfo '%s' but found '%s'", expectedResults.ProcessorInfo, hostInfo.ProcessorInfo)
	}

	if hostInfo.ProcessorFlags != expectedResults.ProcessorFlags {
		t.Errorf("Expected ProcessFlags '%s' but found '%s'", expectedResults.ProcessorFlags, hostInfo.ProcessorFlags)
	}

	// jsonData, err := json.MarshalIndent(hostInfo, "", "  ")
	// if err != nil {
	// 	t.Error(err)
	// }

	// t.Log(string(jsonData))

}

func TestWhitley(t *testing.T) {

	smbiosData = "test_data/whitley/DMI"

	expectedResults := model.HostInfo{
		BiosName:       "Intel Corporation",
		BiosVersion:    "WLYDCRB1.SYS.0020.P33.2012300522",
		HardwareUUID:   "88888888-8887-1615-0115-071ba5a5a5a5",
		ProcessorInfo:  "A6 06 06 00 FF FB EB BF",
		ProcessorFlags: "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
	}

	testSMBIOS(t, &expectedResults)
}

func TestPurley(t *testing.T) {

	smbiosData = "test_data/purley/DMI"

	expectedResults := model.HostInfo{
		BiosName:       "Intel Corporation",
		BiosVersion:    "SE5C620.86B.00.01.6016.032720190737",
		HardwareUUID:   "8032632b-8fa4-e811-906e-00163566263e",
		ProcessorInfo:  "54 06 05 00 FF FB EB BF",
		ProcessorFlags: "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
	}

	testSMBIOS(t, &expectedResults)
}
