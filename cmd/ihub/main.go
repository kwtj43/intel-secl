/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub"

	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, secLogFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open/create %s", LogFile)
	}
	err = os.Chmod(LogFile, 0664)
	if err != nil {
		return nil, nil, fmt.Errorf("error in setting file permission for file : %s", LogFile)
	}

	secLogFile, err = os.OpenFile(SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open/create %s", SecurityLogFile)
	}
	err = os.Chmod(SecurityLogFile, 0664)
	if err != nil {
		return nil, nil, fmt.Errorf("error in setting file permission for file : %s", SecurityLogFile)
	}

	// Containers are always run as non root users, does not require changing ownership of log directories
	if _, err := os.Stat("/.container-env"); err == nil {
		return logFile, secLogFile, nil
	}

	ihubUser, err := user.Lookup(ServiceUserName)
	if err != nil {
		return nil, nil, fmt.Errorf("could not find user '%s'", ServiceUserName)
	}

	uid, err := strconv.Atoi(ihubUser.Uid)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse ihub user id '%s'", ihubUser.Uid)
	}

	gid, err := strconv.Atoi(ihubUser.Gid)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse ihub group id '%s'", ihubUser.Gid)
	}

	err = os.Chown(SecurityLogFile, uid, gid)
	if err != nil {
		return nil, nil, fmt.Errorf("could not change file ownership for file: '%s'", SecurityLogFile)
	}
	err = os.Chown(LogFile, uid, gid)
	if err != nil {
		return nil, nil, fmt.Errorf("could not change file ownership for file: '%s'", LogFile)
	}

	return
}

func main() {
	var app *ihub.App
	logFile, secLogFile, err := openLogFiles()
	if err != nil {
		fmt.Println("Error in setting up Log files :", err.Error())
		app = &ihub.App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			closeLogFiles(logFile, secLogFile)
		}()
		app = &ihub.App{
			LogWriter:    logFile,
			SecLogWriter: secLogFile,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error : ", err.Error())
		closeLogFiles(logFile, secLogFile)
		os.Exit(1)
	}
}

func closeLogFiles(logFile, secLogFile *os.File) {
	var err error
	err = logFile.Close()
	if err != nil {
		fmt.Println("Failed to close default log file:", err.Error())
	}
	err = secLogFile.Close()
	if err != nil {
		fmt.Println("Failed to close security log file:", err.Error())
	}
}
