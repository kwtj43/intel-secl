/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

// osInfoParser collects the HostInfo's OSName and OSVersion fields
// from /etc/os-release file (formatted as described in
// https://www.freedesktop.org/software/systemd/man/os-release.html).
type osInfoParser struct {
	lineReader *bufio.Reader
}

func (osInfoParser *osInfoParser) Init() error {
	file, err := os.Open(osReleaseFile)
	if err != nil {
		return fmt.Errorf("Failed to open os-release file '%s'", osReleaseFile)
	}

	osInfoParser.lineReader = bufio.NewReader(file)
	return nil
}

func (osInfoParser *osInfoParser) Parse(hostInfo *model.HostInfo) error {
	for {
		line, err := osInfoParser.lineReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			return fmt.Errorf("Error parsing os information: %w", err)
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		split := strings.Split(line, "=")
		if len(split) != 2 {
			return fmt.Errorf("'%s' is not a valid os-release line", line)
		}

		if split[0] == "NAME" {
			hostInfo.OSName = strings.ReplaceAll(split[1], "\"", "")
		} else if split[0] == "VERSION_ID" {
			hostInfo.OSVersion = strings.ReplaceAll(split[1], "\"", "")
		}
	}

	return nil
}
