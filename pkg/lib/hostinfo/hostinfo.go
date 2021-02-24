package hostinfo

import (
	"fmt"
	"os"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

// go build -ldflags "-X intel-secl/hostinfo.smbiosData=/tmp/dmi.bin" main.go
// go build -ldflags "-X intel-secl/hostinfo.presetOSName=tep" main.go

var (
	presetOSName = ""
)

type HostInfoParser interface {
	Parse() (*model.HostInfo, error)
}

func NewHostInfoParser() (HostInfoParser, error) {

	if _, err := os.Stat(smbiosData); os.IsNotExist(err) {
		return nil, fmt.Errorf("Could not open file %s: %v\n", smbiosData, err)
	}

	hostInfoParser := hostInfoParser{}

	return &hostInfoParser, nil
}

type hostInfoParser struct {
}

func (this *hostInfoParser) Parse() (*model.HostInfo, error) {

	hostInfo := model.HostInfo{}

	smbiosReader, err := newSMBIOSReader(&hostInfo)
	if err != nil {
		return nil, fmt.Errorf("Could not create SMBIOS reader: %v", err)
	}

	err = smbiosReader.Read()
	if err != nil {
		return nil, fmt.Errorf("Failed to parse SMBIOS: %v", err)
	}

	if presetOSName != "" {
		hostInfo.OSName = presetOSName
	}

	return &hostInfo, nil
}
