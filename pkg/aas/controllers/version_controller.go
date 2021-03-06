/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/version"
	"net/http"
)

type VersionController struct {
}

func (controller VersionController) GetVersion(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	return verStr, http.StatusOK, nil
}
