/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kmipclient

type KmipClient interface {
	InitializeClient(string, string, string, string, string, string) error
	CreateSymmetricKey(int, int) (string, error)
	DeleteKey(string) error
	GetKey(string, string, int) ([]byte, error)
}
