/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package os

import (
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
)

// ChownR method is used to change the ownership of all the file in a directory
func ChownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}

// Copy the src file to dst. Any existing file will be overwritten and will not
// copy file attributes.
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		derr := in.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		derr := out.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return nil
}

func GetDirFileContents(dir, pattern string) ([][]byte, error) {
	dirContents := make([][]byte, 0)
	//if we are passed in an empty pattern, set pattern to * to match all files
	if pattern == "" {
		pattern = "*"
	}

	err := filepath.Walk(dir, func(fPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, _ := path.Match(pattern, info.Name()); matched == true {
			if content, err := ioutil.ReadFile(fPath); err == nil {
				dirContents = append(dirContents, content)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(dirContents) == 0 {
		return nil, fmt.Errorf("did not find any files with matching pattern %s for directory %s", pattern, dir)
	}
	return dirContents, nil
}

func ChownDirForUser(serviceUserName, configDir string) error {
	svcUser, err := user.Lookup(serviceUserName)
	if err != nil {
		return errors.Wrapf(err, "Could not find service user '%s'", serviceUserName)
	}
	uid, err := strconv.Atoi(svcUser.Uid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user uid '%s'", svcUser.Uid)
	}
	gid, err := strconv.Atoi(svcUser.Gid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user gid '%s'", svcUser.Gid)
	}
	err = ChownR(configDir, uid, gid)
	if err != nil {
		return errors.Wrap(err, "Error while changing ownership of files inside config directory")
	}
	return nil
}
