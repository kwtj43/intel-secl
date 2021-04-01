/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

type QuoteReportCache struct {
	QuoteDigest  string
	TrustPcrList []int
	TrustReport  *hvs.TrustReport
}
