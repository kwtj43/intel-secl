/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/setup"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	Config *config.Configuration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
	LogWriter     io.Writer
	SecLogWriter  io.Writer
	HTTPLogWriter io.Writer
}

func (app *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			defaultLog.Errorf("Panic occurred: %+v", err)
		}
	}()
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceName)
		app.printUsageWithError(err)
		return err
	}
	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		app.printUsageWithError(err)
		return err
	case "help", "-h", "--help":
		app.printUsage()
		return nil
	case "version", "-v", "--version":
		app.printVersion()
		return nil
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.startServer()
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.status()
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
		return app.uninstall(purge)
	case "setup":
		if err := app.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				app.printUsageWithError(err)
			} else {
				fmt.Fprintln(app.errorWriter(), err.Error())
			}
			return err
		}
	}
	return nil
}

func (app *App) consoleWriter() io.Writer {
	if app.ConsoleWriter != nil {
		return app.ConsoleWriter
	}
	return os.Stdout
}

func (app *App) errorWriter() io.Writer {
	if app.ErrorWriter != nil {
		return app.ErrorWriter
	}
	return os.Stderr
}

func (app *App) secLogWriter() io.Writer {
	if app.SecLogWriter != nil {
		return app.SecLogWriter
	}
	return os.Stdout
}

func (app *App) logWriter() io.Writer {
	if app.LogWriter != nil {
		return app.LogWriter
	}
	return os.Stderr
}

func (app *App) httpLogWriter() io.Writer {
	if app.HTTPLogWriter != nil {
		return app.HTTPLogWriter
	}
	return os.Stderr
}

func (app *App) configuration() *config.Configuration {
	if app.Config != nil {
		return app.Config
	}
	viper.AddConfigPath(app.configDir())
	config, err := config.LoadConfiguration()
	if err == nil {
		app.Config = config
		return app.Config
	}
	return nil
}

func (app *App) configureLogs(stdOut, logFile bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = app.logWriter()
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, app.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, app.secLogWriter())

	logConfig := app.Config.Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	defaultLog.Info(commLogMsg.LogInit)
	return nil
}

func (app *App) start() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl start kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "start", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) stop() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl stop kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "stop", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) status() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl status kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "status", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
