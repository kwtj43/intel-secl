/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package skchvsclient

import (
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/util"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

//Client Details for skchvsclient
type Client struct {
	BaseURL   *url.URL
	AASURL    *url.URL
	UserName  string
	Password  string
	CertArray []x509.Certificate
}

//GetSGXPlatformData Get SGX Platform data
func (c Client) GetSGXPlatformData(url string) ([]byte, error) {
	log.Trace("skchvsclient/skc_client:GetSGXPlatformData() Entering")
	defer log.Trace("skchvsclient/skc_client:GetSGXPlatformData() Leaving")

	// Create a new request using http
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "skchvsclient/skc_client:GetSGXPlatformData() Error Forming request")
	}
	req.Header.Add("Accept", "application/json")

	response, err := util.SendRequest(req, c.AASURL.String(), c.UserName, c.Password, c.CertArray)
	if err != nil {
		return nil, errors.Wrap(err, "skchvsclient/skc_client:GetSGXPlatformData() Error reading response body while fetching platform data")
	}

	return response, nil
}

func (c Client) GetSHVSVersion(url string) ([]byte, error) {
	log.Trace("skchvsclient/skc_client:GetSHVSVersion() Entering")
	defer log.Trace("skchvsclient/skc_client:GetSHVSVersion() Leaving")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "skchvsclient/skc_client:GetSHVSVersion() Error forming request")
	}
	response, err := util.SendNoAuthRequest(req, c.CertArray)
	if err != nil {
		return nil, errors.Wrap(err, "skchvsclient/skc_client:GetSHVSVersion() Error reading response body while fetching the version")
	}
	return response, nil
}
