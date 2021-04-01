/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kmipclient

// //The following CFLAGS require 'export CGO_CFLAGS_ALLOW="-f.*"' in the executable that uses kmip-client (i.e. kbs).
// #cgo CFLAGS: -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -lssl -lcrypto -lkmip -Wl,-rpath=\$ORIGIN/../lib
// #include <stdlib.h>
// #include "kmipclient.h"
import "C"

import (
	"bytes"
	"unsafe"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()

type kmipClient struct {
	KMIPVersion int
}

func NewKmipClient() KmipClient {
	return &kmipClient{}
}

var SupportedKmipVersions = map[string]int{"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3, "1.4": 4, "2.0": 5}

// InitializeClient initializes all the values required for establishing connection to kmip server
func (kc *kmipClient) InitializeClient(version, serverIP, serverPort, clientCert, clientKey, rootCert string) error {
	defaultLog.Trace("kmipclient/kmipclient:InitializeClient() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:InitializeClient() Leaving")

	var present bool
	kc.KMIPVersion, present = SupportedKmipVersions[version]
	if !present {
		return errors.New("kmipclient/kmipclient:InitializeClient() Invalid Kmip version provided")
	}

	address := C.CString(serverIP)
	defer C.free(unsafe.Pointer(address))

	port := C.CString(serverPort)
	defer C.free(unsafe.Pointer(port))

	certificate := C.CString(clientCert)
	defer C.free(unsafe.Pointer(certificate))

	key := C.CString(clientKey)
	defer C.free(unsafe.Pointer(key))

	ca := C.CString(rootCert)
	defer C.free(unsafe.Pointer(ca))

	result := C.kmipw_init((*C.char)(address), (*C.char)(port), (*C.char)(certificate), (*C.char)(key), (*C.char)(ca))
	if result != constants.KMIP_CLIENT_SUCCESS {
		return errors.New("kmipclient/kmipclient:InitializeClient() Failed to initialize kmip client. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:InitializeClient() Kmip client initialized")
	return nil
}

// CreateSymmetricKey creates a symmetric key on kmip server
func (kc *kmipClient) CreateSymmetricKey(alg, length int) (string, error) {
	defaultLog.Trace("kmipclient/kmipclient:CreateSymmetricKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:CreateSymmetricKey() Leaving")

	algId := C.int(alg)
	algLength := C.int(length)

	keyID := C.kmipw_create(algId, algLength, (C.int)(kc.KMIPVersion))
	if keyID == nil {
		return "", errors.New("Failed to create symmetric key on kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:CreateSymmetricKey() Created symmetric key on kmip server")
	kmipId := C.GoString(keyID)
	return kmipId, nil
}

// DeleteKey deletes a key from kmip server
func (kc *kmipClient) DeleteKey(id string) error {
	defaultLog.Trace("kmipclient/kmipclient:DeleteKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:DeleteKey() Leaving")

	keyId := C.CString(id)
	defer C.free(unsafe.Pointer(keyId))

	result := C.kmipw_destroy(keyId, (C.int)(kc.KMIPVersion))
	if result != constants.KMIP_CLIENT_SUCCESS {
		return errors.New("Failed to delete key from kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:DeleteKey() Deleted key from kmip server")
	return nil
}

// GetKey retrieves a key from kmip server
func (kc *kmipClient) GetKey(id string, algorithm string, keyLength int) ([]byte, error) {
	defaultLog.Trace("kmipclient/kmipclient:GetKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:GetKey() Leaving")

	keyID := C.CString(id)
	defer C.free(unsafe.Pointer(keyID))

	keyAlgorithm := C.CString(algorithm)
	defer C.free(unsafe.Pointer(keyAlgorithm))

	if algorithm == constants.CRYPTOALG_AES {
		keyLength = keyLength / 8
	} else {
		keyLength = keyLength / 8 * 5
	}

	keyBuffer := C.malloc(C.ulong(keyLength))
	defer C.free(unsafe.Pointer(keyBuffer))

	result := C.kmipw_get((*C.char)(keyID), (*C.char)(keyBuffer), (*C.char)(keyAlgorithm), (C.int)(kc.KMIPVersion))
	if result != constants.KMIP_CLIENT_SUCCESS {
		return nil, errors.New("Failed to retrieve key from kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:GetKey() Retrieved  key from kmip server")
	key := C.GoBytes(keyBuffer, C.int(keyLength))

	// Removing empty bytes from buffer
	return bytes.Trim(key, "\x00"), nil
}
