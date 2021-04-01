/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/google/uuid"

type HostCollection struct {
	Hosts []*Host `json:"hosts" xml:"host"`
}

type Host struct {
	// swagger:strfmt uuid
	Id               uuid.UUID `json:"id,omitempty"`
	HostName         string    `json:"host_name"`
	Description      string    `json:"description,omitempty"`
	ConnectionString string    `json:"connection_string"`
	// swagger:strfmt uuid
	HardwareUuid     *uuid.UUID             `json:"hardware_uuid,omitempty"`
	FlavorgroupNames []string               `json:"flavorgroup_names,omitempty"`
	Report           *TrustReport           `json:"report,omitempty"`
	Trusted          *bool                  `json:"trusted,omitempty"`
	ConnectionStatus *HostStatusInformation `json:"status,omitempty"`
}

type HostCreateRequest struct {
	HostName         string   `json:"host_name"`
	Description      string   `json:"description,omitempty"`
	ConnectionString string   `json:"connection_string"`
	FlavorgroupNames []string `json:"flavorgroup_names,omitempty"`
}

type HostFlavorgroupCollection struct {
	HostFlavorgroups []HostFlavorgroup `json:"flavorgroup_host_links" xml:"flavorgroup_host_link"`
}

type HostFlavorgroup struct {
	// swagger:strfmt uuid
	HostId uuid.UUID `json:"host_id,omitempty"`
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}

type HostFlavorgroupCreateRequest struct {
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}
