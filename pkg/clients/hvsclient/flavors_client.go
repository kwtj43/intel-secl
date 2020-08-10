/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvsclient

import (
	"bytes"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type FlavorsClient interface {

	CreateFlavor(flavorCreateRequest *models.FlavorCreateRequest) (hvs.FlavorCollection, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type flavorsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *flavorsClientImpl) CreateFlavor(flavorCreateRequest *models.FlavorCreateRequest) (hvs.FlavorCollection, error) {
	log.Trace("hvsclient/flavors_client:CreateFlavor() Entering")
	defer log.Trace("hvsclient/flavors_client:CreateFlavor() Leaving")

	var flavors hvs.FlavorCollection
	jsonData, err := json.Marshal(flavorCreateRequest)
	if err != nil {
		return flavors, err
	}
	url, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return flavors, errors.Wrap(err, "hvsclient/flavors_client:CreateFlavor() error parsing base url")
	}

	url.Path = path.Join(url.Path, "flavors")
	request, _ := http.NewRequest("POST", url.String(), bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer " + client.cfg.BearerToken)

	log.Debugf("hvsclient/flavors_client:CreateFlavor() Posting to url %s, json: %s ", url, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return flavors, errors.Wrapf(err, "hvsclient/flavors_client:CreateFlavor() Error while making request to %s", url)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return flavors, errors.Errorf("hvsclient/flavors_client:CreateFlavor() request made to %s returned status %d", url, response.StatusCode)
	}

	jsonData, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return flavors, errors.Errorf("hvsclient/flavors_client:CreateFlavor() Error reading response")
	}

	log.Debugf("hvsclient/flavors_client:CreateFlavor() Json response body returned: %s", string(jsonData))


	err = json.Unmarshal(jsonData, &flavors)
	if err != nil {
		return flavors, errors.Wrap(err,"hvsclient/flavors_client:CreateFlavor() Error unmarshalling json data to flavors")
	}
	return flavors, nil
}