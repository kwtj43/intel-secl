/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()

func NewKeyManager(cfg *config.KmipConfig, provider string) (KeyManager, error) {
	defaultLog.Trace("keymanager/key_manager:NewKeyManager() Entering")
	defer defaultLog.Trace("keymanager/key_manager:NewKeyManager() Leaving")

	if strings.ToLower(provider) == constants.KmipKeyManager {
		kmipClient := kmipclient.NewKmipClient()
		err := kmipClient.InitializeClient(cfg.Version, cfg.ServerIP, cfg.ServerPort, cfg.ClientCert, cfg.ClientKey, cfg.RootCert)
		if err != nil {
			return nil, errors.Wrap(err, "keymanager/key_manager:NewKeyManager() Failed to initialize client")
		}
		return &KmipManager{kmipClient}, nil
	} else {
		return &DirectoryManager{}, nil
	}
}

type KeyManager interface {
	CreateKey(*kbs.KeyRequest) (*models.KeyAttributes, error)
	DeleteKey(*models.KeyAttributes) error
	RegisterKey(*kbs.KeyRequest) (*models.KeyAttributes, error)
	TransferKey(*models.KeyAttributes) ([]byte, error)
}
