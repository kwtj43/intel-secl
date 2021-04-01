/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"time"
)

type MockHostTrustManager struct{}

func (mock *MockHostTrustManager) VerifyHost(hostId uuid.UUID, fetchHostData bool, preferHashMatch bool) (*models.HVSReport, error) {
	store := mocks.NewMockReportStore()
	report, _ := store.Search(&models.ReportFilterCriteria{HostID: hostId})
	return &report[0], nil
}

func (mock *MockHostTrustManager) VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error {
	// put in a small delay
	time.Sleep(time.Duration(250 * time.Millisecond))
	return nil
}

func (mock *MockHostTrustManager) ProcessQueue() error {
	return nil
}
