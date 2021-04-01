/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
)

type CreateDefaultFlavorTemplate struct {
	DBConf  commConfig.DBConfig
	deleted []string

	commandName   string
	TemplateStore *postgres.FlavorTemplateStore
}

var defaultFlavorTemplateNames = []string{
	"default-linux-tpm20-tboot",
	"default-linux-tpm20-suefi",
	"default-linux-tpm20-cbnt",
	"default-uefi",
	"default-bmc",
	"default-pfr",
	"default-esxi-tpm12",
	"default-esxi-tpm20",
}

func (t *CreateDefaultFlavorTemplate) Run() error {
	var templates []hvs.FlavorTemplate
	var ftList []hvs.FlavorTemplate

	if t.TemplateStore == nil {
		err := t.flavorTemplateStore()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize flavor template store instance")
		}
	}

	if len(t.deleted) != 0 {
		// Recover deleted default template.
		err := t.TemplateStore.Recover(t.deleted)
		if err != nil {
			return errors.Wrapf(err, "Failed to recover default flavor template(s) %s", t.deleted)
		}
		t.deleted = []string{}
		return nil
	}

	templates, err := getTemplates()
	if err != nil {
		return err
	}

	for _, ft := range templates {
		ftc := models.FlavorTemplateFilterCriteria{Label: ft.Label}
		ftList, err = t.TemplateStore.Search(&ftc)
		if err != nil {
			return errors.Wrap(err, "Failed to search the default flavor template(s)")
		}
		if len(ftList) == 0 {
			_, err := t.TemplateStore.Create(&ft)
			if err != nil {
				return errors.Wrap(err, "Failed to create default flavor template with ID \""+ft.ID.String()+"\"")
			}
		}
	}

	return nil
}

func (t *CreateDefaultFlavorTemplate) Validate() error {

	var ftList []hvs.FlavorTemplate
	defaultFlavorTemplateMap := map[string]bool{}
	t.deleted = []string{}
	var err error

	if t.TemplateStore == nil {
		err := t.flavorTemplateStore()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize flavor template store instance")
		}
	}

	for _, templateName := range defaultFlavorTemplateNames {
		defaultFlavorTemplateMap[templateName] = false
	}

	ftc := models.FlavorTemplateFilterCriteria{IncludeDeleted: false}
	ftList, err = t.TemplateStore.Search(&ftc)
	if err != nil {
		return errors.Wrap(err, "Failed to validate "+t.commandName)
	}
	if len(ftList) == 0 {
		return errors.New("No active templates found in db")
	}

	for _, template := range ftList {
		defaultFlavorTemplateMap[template.Label] = true
	}

	for _, templateName := range defaultFlavorTemplateNames {
		if !defaultFlavorTemplateMap[templateName] {
			t.deleted = append(t.deleted, templateName)
		}
	}

	if len(t.deleted) != 0 {
		return errors.New(t.commandName + ": Failed to recover deleted default flavor template(s) \"" + strings.Join(t.deleted, " "))
	}
	return nil
}

func (t *CreateDefaultFlavorTemplate) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, "", DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *CreateDefaultFlavorTemplate) SetName(n, e string) {
	t.commandName = n
}

func (t *CreateDefaultFlavorTemplate) flavorTemplateStore() error {
	var dataStore *postgres.DataStore
	var err error
	if t.TemplateStore == nil {
		dataStore, err = postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &t.DBConf))
		if err != nil {
			return errors.Wrap(err, "Failed to connect database")
		}
		t.TemplateStore = postgres.NewFlavorTemplateStore(dataStore)
	}
	if t.TemplateStore.Store == nil {
		return errors.New("Failed to create FlavorTemplateStore")
	}
	return nil
}

func getTemplates() ([]hvs.FlavorTemplate, error) {
	var ret []hvs.FlavorTemplate

	defaultFlavorTemplatesRaw, err := readDefaultTemplates()
	if err != nil {
		return nil, err
	}

	for _, ftStr := range defaultFlavorTemplatesRaw {
		var ft hvs.FlavorTemplate
		err := json.Unmarshal([]byte(ftStr), &ft)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ft)
	}
	return ret, nil
}

// readDefaultTemplates This method is used to read the default template json files
func readDefaultTemplates() ([]string, error) {
	var defaultFlavorTemplatesRaw []string

	flavorTemplatesPath, err := ioutil.ReadDir(constants.DefaultFlavorTemplatesDirectory)
	if err != nil {
		return nil, err
	}

	for _, flavorTemplatePath := range flavorTemplatesPath {
		flavorTemplateBytes, err := ioutil.ReadFile(constants.DefaultFlavorTemplatesDirectory + flavorTemplatePath.Name())
		if err != nil {
			return nil, err
		}
		defaultFlavorTemplatesRaw = append(defaultFlavorTemplatesRaw, string(flavorTemplateBytes))
	}
	return defaultFlavorTemplatesRaw, nil
}
