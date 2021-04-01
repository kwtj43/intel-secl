/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestKmipManager_CreateKey(t *testing.T) {
	assert := assert.New(t)

	keyInfo := &kbs.KeyInformation{
		Algorithm: "AES",
		KeyLength: 256,
	}

	keyRequest := &kbs.KeyRequest{
		KeyInformation: keyInfo,
	}

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)

	keyManager := &KmipManager{mockClient}

	keyAttributes, err := keyManager.CreateKey(keyRequest)
	assert.NoError(err)
	assert.Equal("1", keyAttributes.KmipKeyID)
}

func TestKmipManager_DeleteKey(t *testing.T) {
	assert := assert.New(t)

	keyAttributes := &models.KeyAttributes{
		KmipKeyID: "1",
	}

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("DeleteKey", mock.Anything).Return(nil)

	keyManager := &KmipManager{mockClient}

	err := keyManager.DeleteKey(keyAttributes)
	assert.NoError(err)
}

func TestKmipManager_RegisterKey(t *testing.T) {
	assert := assert.New(t)

	keyInfo := &kbs.KeyInformation{
		Algorithm: "AES",
		KmipKeyID: "1",
	}

	keyRequest := &kbs.KeyRequest{
		KeyInformation: keyInfo,
	}

	mockClient := kmipclient.NewMockKmipClient()

	keyManager := &KmipManager{mockClient}

	keyAttributes, err := keyManager.RegisterKey(keyRequest)
	assert.NoError(err)
	assert.Equal("1", keyAttributes.KmipKeyID)
}

func TestKmipManager_TransferKey(t *testing.T) {
	assert := assert.New(t)

	keyAttributes := &models.KeyAttributes{
		Algorithm: "AES",
		KmipKeyID: "1",
	}

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)

	keyManager := &KmipManager{mockClient}

	key, err := keyManager.TransferKey(keyAttributes)
	assert.NoError(err)
	assert.Equal([]byte(""), key)
}
