/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bufio"
	"io"
	"os"
	"strings"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

// osInfoParser collects the HostInfo's OSName and OSVersion fields
// from /etc/os-release file (formatted as described in
// https://www.freedesktop.org/software/systemd/man/os-release.html).
type osInfoParser struct{}

func (osInfoParser *osInfoParser) Init() error {
	if _, err := os.Stat(osReleaseFile); os.IsNotExist(err) {
		return errors.Errorf("Could not find os-release file %q", osReleaseFile)
	}

	return nil
}

func (osInfoParser *osInfoParser) Parse(hostInfo *model.HostInfo) error {
	var err error

	file, err := os.Open(osReleaseFile)
	if err != nil {
		return errors.Errorf("Failed to open os-release file %q", osReleaseFile)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Errorf("Failed close os-release file %q: %s", osReleaseFile, err.Error())
		}
	}()

	lineReader := bufio.NewReader(file)

	for {
		line, err := lineReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			return errors.Wrapf(err, "Error parsing os information from file %q", osReleaseFile)
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		split := strings.Split(line, "=")
		if len(split) != 2 {
			return errors.Errorf("%q is not a valid line in file %q", line, osReleaseFile)
		}

		if split[0] == "NAME" {
			hostInfo.OSName = strings.ReplaceAll(split[1], "\"", "")

			// TODO: os-release contains NAME="Red Hat Enterprise Linux" where 'lsbrelease' returned
			// RedHatEnterprise.  Strip out the strings and consider adding a field in hostinfo that
			// indicates the "linux" vs. "windows" vs. ???.
			hostInfo.OSName = strings.ReplaceAll(hostInfo.OSName, " ", "")
		} else if split[0] == "VERSION_ID" {
			hostInfo.OSVersion = strings.ReplaceAll(split[1], "\"", "")
		}
	}

	// TODO:  This is a hack to get flavor-tempates (using "RedHatEnterprise").  We should
	// add "os_type:linux" and update the templates.
	if hostInfo.OSName == "RedHatEnterpriseLinux" {
		hostInfo.OSName = "RedHatEnterprise"
	}

	return nil
}
