/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type DirectoryManager struct {
}

func (dm *DirectoryManager) CreateKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/directory_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:CreateKey() Leaving")

	keyAttributes := &models.KeyAttributes{
		Algorithm:        request.KeyInformation.Algorithm,
		TransferPolicyId: request.TransferPolicyID,
		Label:            request.Label,
		Usage:            request.Usage,
	}

	var err error
	if request.KeyInformation.Algorithm == constants.CRYPTOALG_AES {
		keyBytes, err := generateAESKey(request.KeyInformation.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "Could not generate AES key")
		}

		keyAttributes.KeyLength = request.KeyInformation.KeyLength
		keyAttributes.KeyData = base64.StdEncoding.EncodeToString(keyBytes)
	} else {

		var public crypto.PublicKey
		var private crypto.PrivateKey
		if request.KeyInformation.Algorithm == constants.CRYPTOALG_RSA {
			private, public, err = generateRSAKeyPair(request.KeyInformation.KeyLength)
			if err != nil {
				return nil, errors.Wrap(err, "Could not generate RSA keypair")
			}
			keyAttributes.KeyLength = request.KeyInformation.KeyLength
		} else {
			private, public, err = generateECKeyPair(request.KeyInformation.CurveType)
			if err != nil {
				return nil, errors.Wrap(err, "Could not generate EC keypair")
			}
			keyAttributes.CurveType = request.KeyInformation.CurveType
		}

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal private key")
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal public key")
		}

		keyAttributes.PrivateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)
		keyAttributes.PublicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes.ID = newUuid
	keyAttributes.CreatedAt = time.Now().UTC()

	return keyAttributes, nil
}

func (dm *DirectoryManager) DeleteKey(attributes *models.KeyAttributes) error {
	defaultLog.Trace("keymanager/directory_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:DeleteKey() Leaving")

	return nil
}

func (dm *DirectoryManager) RegisterKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/directory_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:RegisterKey() Leaving")

	if request.KeyInformation.KeyString == "" {
		return nil, errors.New("key_string cannot be empty for register operation in directory mode")
	}

	var key, publicKey, privateKey string
	if request.KeyInformation.Algorithm == constants.CRYPTOALG_AES {
		key = request.KeyInformation.KeyString
	} else {

		var public crypto.PublicKey
		var private crypto.PrivateKey
		private, err := crypt.GetPrivateKeyFromPem([]byte(request.KeyInformation.KeyString))
		if err != nil {
			return nil, errors.Wrap(err, "Failed to decode private key")
		}

		if request.KeyInformation.Algorithm == constants.CRYPTOALG_RSA {
			rsaKey, ok := private.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.Wrap(err, "Private key in request is not RSA key")
			}

			public = &rsaKey.PublicKey
		} else {
			ecKey, ok := private.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.Wrap(err, "Private key in request is not EC key")
			}

			public = &ecKey.PublicKey
		}

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal private key")
		}
		privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal public key")
		}
		publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &models.KeyAttributes{
		ID:               newUuid,
		Algorithm:        request.KeyInformation.Algorithm,
		KeyLength:        request.KeyInformation.KeyLength,
		KeyData:          key,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Label:            request.Label,
		Usage:            request.Usage,
	}

	return keyAttributes, nil
}

func (dm *DirectoryManager) TransferKey(attributes *models.KeyAttributes) ([]byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:TransferKey() Leaving")

	var key string
	if attributes.Algorithm == constants.CRYPTOALG_AES {
		key = attributes.KeyData
	} else {
		key = attributes.PrivateKey
	}

	return base64.StdEncoding.DecodeString(key)
}

func generateAESKey(length int) ([]byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateAESKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateAESKey() Leaving")

	return crypt.GetRandomBytes(length / 8)
}

func generateRSAKeyPair(length int) (crypto.PrivateKey, crypto.PublicKey, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateRSAKeyPair() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateRSAKeyPair() Leaving")

	private, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, err
	}

	public := &private.PublicKey
	if bits := private.N.BitLen(); bits != length {
		return nil, nil, errors.Errorf("key too short (%d vs %d)", bits, length)
	}

	return private, public, nil
}

func generateECKeyPair(curveType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateECKeyPair() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateECKeyPair() Leaving")

	var curve elliptic.Curve
	switch curveType {
	case "prime256v1", "secp256r1":
		curve = elliptic.P256()
	case "secp384r1":
		curve = elliptic.P384()
	case "secp521r1":
		curve = elliptic.P521()
	default:
		return nil, nil, errors.New("unsupported curve type")
	}

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	public := &private.PublicKey
	if !curve.IsOnCurve(public.X, public.Y) {
		return nil, nil, errors.New("public key invalid")
	}

	return private, public, nil
}
