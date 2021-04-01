/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package session

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/pkg/errors"
)

type QuoteData struct {
	QuoteBlob string `json:"quote"`
	UserData  string `json:"userData"`
}

// SessionCreateSwk - Function to create swk
func SessionCreateSwk() ([]byte, error) {

	defaultLog.Trace("session/session_management:SessionCreateSwk() Entering")
	defer defaultLog.Trace("session/session_management:SessionCreateSwk() Leaving")

	//create an AES Key here of 256 bytes
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "session/session_management:SessionCreateSwk() Failed to read the key bytes")
	}

	return keyBytes, nil
}

// SessionWrapSwkWithRSAKey - Function to wrap the swk key with rsa key
func SessionWrapSwkWithRSAKey(challengeType string, publicKey []byte, swk []byte) ([]byte, error) {
	defaultLog.Trace("session/session_management:SessionWrapSwkWithRSAKey() Entering")
	defer defaultLog.Trace("session/session_management:SessionWrapSwkWithRSAKey() Leaving")

	rsaPubKey, err := crypt.GetPublicKeyFromPem(publicKey)
	if err != nil {
		secLog.WithError(err).Errorf("session/session_management:SessionWrapSwkWithRSAKey() %s : Public key decode failed", commLogMsg.InvalidInputBadParam)
		return nil, errors.Wrap(err, "Failed to decode public key")
	}

	rsaKey, ok := rsaPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Wrap(err, "session/session_management:SessionWrapSwkWithRSAKey() Invalid PEM passed in from user, should be RSA.")
	}

	cipherText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaKey, swk, nil)
	if err != nil {
		return nil, errors.Wrap(err, "session/session_management:SessionWrapSwkWithRSAKey() Failed to create cipher key")
	}
	return cipherText, nil
}
