/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package models

type HostInfoFetchCriteria struct {
	GetReport      bool
	GetTrustStatus bool
	GetHostStatus  bool
}
