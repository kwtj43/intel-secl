/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type FlavorTemplateStore struct {
	Store *DataStore
}

func NewFlavorTemplateStore(store *DataStore) *FlavorTemplateStore {
	return &FlavorTemplateStore{Store: store}
}

// create
func (ft *FlavorTemplateStore) Create(flavorTemplate *hvs.FlavorTemplate) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Create() Leaving")

	flavorContent := models.FlavorTemplateContent{
		Label:       flavorTemplate.Label,
		Condition:   flavorTemplate.Condition,
		FlavorParts: flavorTemplate.FlavorParts,
	}

	createdTemplate := FlavorTemplate{
		ID:      uuid.New(),
		Content: PGFlavorTemplateContent(flavorContent),
		Deleted: false,
	}

	flavorTemplate.ID = createdTemplate.ID

	if err := ft.Store.Db.Create(&createdTemplate).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Create() failed to create flavor")
	}
	return flavorTemplate, nil
}

func (ft *FlavorTemplateStore) Retrieve(templateID uuid.UUID, included bool) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Create() Leaving")

	sf := FlavorTemplate{}
	row := ft.Store.Db.Model(FlavorTemplate{}).Select("id,content,deleted").Where(&FlavorTemplate{ID: templateID}).Row()
	if err := row.Scan(&sf.ID, (*PGFlavorTemplateContent)(&sf.Content), &sf.Deleted); err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Retrieve() - Could not scan record ")
	}
	flavorTemplate := hvs.FlavorTemplate{}

	if (included && sf.Deleted) || (included && !sf.Deleted) || (!included && !sf.Deleted) {
		//if (included || !sf.Deleted) {

		flavorTemplate = hvs.FlavorTemplate{
			ID:          sf.ID,
			Label:       sf.Content.Label,
			Condition:   sf.Content.Condition,
			FlavorParts: sf.Content.FlavorParts,
		}
	}
	if flavorTemplate.ID == uuid.Nil {
		return nil, errors.Errorf("postgres/flavortemplate_store:Retrieve() failed to retrieve record from db, ", commErr.RowsNotFound)
	}
	return &flavorTemplate, nil
}

func (ft *FlavorTemplateStore) Search(included bool) ([]hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Search() Leaving")

	flavortemplates := []hvs.FlavorTemplate{}
	rows, err := ft.Store.Db.Model(FlavorTemplate{}).Select("id,content,deleted").Where(&FlavorTemplate{Deleted: false}).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	for rows.Next() {
		template := FlavorTemplate{}

		if err := rows.Scan(&template.ID, (*PGFlavorTemplateContent)(&template.Content), &template.Deleted); err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() - Could not scan record ")
		}
		//if (included && template.Deleted) || (!included && !template.Deleted) {
		if included || (!included && !template.Deleted) {
			flavorTemplate := hvs.FlavorTemplate{
				ID:          template.ID,
				Label:       template.Content.Label,
				Condition:   template.Content.Condition,
				FlavorParts: template.Content.FlavorParts,
			}
			flavortemplates = append(flavortemplates, flavorTemplate)
		}
	}

	return flavortemplates, nil
}

func (ft *FlavorTemplateStore) Delete(templateID uuid.UUID) error {
	defaultLog.Trace("postgres/flavortemplate_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Delete() Leaving")

	err := ft.Store.Db.Model(FlavorTemplate{}).Where(&FlavorTemplate{ID: templateID}).Update(&FlavorTemplate{Deleted: true}).Error
	if err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:Delete() - Could not Delete record ")
	}

	return nil
}

// // AddFlavorTemplates creates a FlavorGroup-Flavor link
// func (f *FlavorGroupStore) AddFlavorTemplates(fgId uuid.UUID, ftId uuid.UUID) (uuid.UUID, error) {
// 	defaultLog.Trace("postgres/flavorgroup_store:AddFlavorTemplates() Entering")
// 	defer defaultLog.Trace("postgres/flavorgroup_store:AddFlavorTemplates() Leaving")

// 	if fgId == uuid.Nil || ftId == uuid.Nil {
// 		return uuid.Nil, errors.New("postgres/flavorgroup_store:AddFlavorTemplates() ")
// 	}

// 	fgftlink := flavorgroupFlavortemplate{
// 		FlavorgroupID:    fgId,
// 		FlavorTemplateID: ftId,
// 	}

// 	err := f.Store.Db.Model(flavorgroupFlavortemplate{}).Create(&fgftlink).Error
// 	if err != nil {
// 		return uuid.Nil, errors.Wrap(err, "postgres/flavorgroup_store:AddFlavorTemplates() failed to create flavorgroup-flavor association")
// 	}

// 	return ftId, nil
// }
