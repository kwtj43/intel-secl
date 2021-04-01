/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kmipclient

import (
	"github.com/stretchr/testify/mock"
)

// MockKmipClient is a mock of KmipClient interface
type MockKmipClient struct {
	mock.Mock
}

// NewMockKmipClient creates a new mock instance
func NewMockKmipClient() *MockKmipClient {
	return &MockKmipClient{}
}

// InitializeClient mocks base method
func (m *MockKmipClient) InitializeClient(version, serverIP, serverPort, clientKey, clientCert, rootCert string) error {
	args := m.Called(version, serverIP, serverPort, clientKey, clientCert, rootCert)
	return args.Error(0)
}

// CreateSymmetricKey mocks base method
func (m *MockKmipClient) CreateSymmetricKey(alg, length int) (string, error) {
	args := m.Called(alg, length)
	return args.Get(0).(string), args.Error(1)
}

// DeleteSymmetricKey mocks base method
func (m *MockKmipClient) DeleteKey(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// GetSymmetricKey mocks base method
func (m *MockKmipClient) GetKey(id string, algorithm string, keyLength int) ([]byte, error) {
	args := m.Called(id)
	return args.Get(0).([]byte), args.Error(1)
}
