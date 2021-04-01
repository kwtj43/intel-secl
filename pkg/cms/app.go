/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
	"os"
	"os/exec"
	"time"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogInt "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/setup"
	"github.com/pkg/errors"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	ErrorWriter    io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
	SecLogWriter   io.Writer
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}
func (a *App) errorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	viper.AddConfigPath(a.configDir())
	c, err := config.Load()
	if err == nil {
		a.Config = c
		return a.Config
	}
	return nil
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

func (a *App) configureLogs(isStdOut bool, isFileOut bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter
	if isStdOut {
		if isFileOut {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())
	logConfig := a.Config.Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &commLog.LogFormatter{MaxLength: logConfig.MaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &commLog.LogFormatter{MaxLength: logConfig.MaxLength}, ioWriterSecurity, false)

	slog.Info(message.LogInit)
	log.Info(message.LogInit)
	return nil
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		return nil
	}
	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		a.printUsageWithError(err)
		return err
	case "tlscertsha384":
		hash, err := crypt.GetCertHexSha384(constants.TLSCertPath)
		if err != nil {
			return errors.Wrap(err, "app:Run() Could not derive tls certificate digest")
		}
		fmt.Println(hash)
		return nil
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting CMS service")
		}
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.status()
	case "uninstall":
		// the only allowed flag is --purge
		purge := false
		if len(args) == 3 {
			if args[2] != "--purge" {
				return errors.New("Invalid flag: " + args[2])
			}
			purge = true
		} else if len(args) != 2 {
			return errInvalidCmd
		}
		return a.uninstall(purge)
	case "version", "--version", "-v":
		a.printVersion()
		return nil
	case "setup":
		if err := a.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				a.printUsageWithError(err)
			} else {
				fmt.Fprintln(a.errorWriter(), err.Error())
			}
			return err
		}

	}
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:start() Could not locate systemctl to start application service")
	}
	cmd := exec.Command(systemctl, "start", "cms")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:stop() Could not locate systemctl to stop application service")
	}
	cmd := exec.Command(systemctl, "stop", "cms")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:status() Could not locate systemctl to check status of application service")
	}
	cmd := exec.Command(systemctl, "status", "cms")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
