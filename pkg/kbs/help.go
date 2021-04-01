/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/version"
)

const helpStr = `Usage:
	kbs <command> [arguments]
	
Available Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current kbs build
	setup <task>           Run setup task
	start                  Start kbs
	status                 Show the status of kbs
	stop                   Stop kbs
	uninstall [--purge]    Uninstall kbs
		--purge            all configuration and data files will be removed if this flag is set

Usage of kbs setup:
	kbs setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
	all                                 Runs all setup tasks
	download-ca-cert                    Download CMS root CA certificate
	download-cert-tls                   Download CA certificate from CMS for tls
	create-default-key-transfer-policy  Create default key transfer policy for KBS
	update-service-config               Sets or Updates the Service configuration 
`

func (app *App) printUsage() {
	fmt.Fprintln(app.consoleWriter(), helpStr)
}

func (app *App) printUsageWithError(err error) {
	fmt.Fprintln(app.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(app.errorWriter(), helpStr)
}

func (app *App) printVersion() {
	fmt.Fprintf(app.consoleWriter(), version.GetVersion())
}
