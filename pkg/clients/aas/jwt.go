/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	types "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
)

type JWTClientErr struct {
	ErrMessage string
	ErrInfo    string
}

func (ucErr *JWTClientErr) Error() string {
	return fmt.Sprintf("%s: %s", ucErr.ErrMessage, ucErr.ErrInfo)
}

var (
	ErrHTTPGetJWTCert = &clients.HTTPClientErr{
		ErrMessage: "Failed to retrieve JWT signing certificate",
	}
	ErrHTTPFetchJWTToken = &clients.HTTPClientErr{
		ErrMessage: "Failed to retrieve JWT token from aas",
	}
	ErrUserNotFound = &JWTClientErr{
		ErrMessage: "User name not registered",
		ErrInfo:    "",
	}
	ErrJWTNotYetFetched = &JWTClientErr{
		ErrMessage: "User token not yet fetched",
		ErrInfo:    "",
	}
)

type jwtClient struct {
	BaseURL    string
	HTTPClient *http.Client

	users  map[string]*types.UserCred
	tokens map[string][]byte
}

func NewJWTClient(url string) *jwtClient {

	ret := jwtClient{BaseURL: url}
	ret.users = make(map[string]*types.UserCred)
	ret.tokens = make(map[string][]byte)
	return &ret
}

func (c *jwtClient) AddUser(username, password string) {
	c.users[username] = &types.UserCred{
		UserName: username,
		Password: password,
	}
}

func (c *jwtClient) GetUserToken(username string) ([]byte, error) {

	if _, ok := c.users[username]; !ok {
		ErrUserNotFound.ErrInfo = username
		return nil, ErrUserNotFound
	}
	token, ok := c.tokens[username]
	if ok {
		return token, nil
	}
	ErrJWTNotYetFetched.ErrInfo = username
	return nil, ErrJWTNotYetFetched
}

func (c *jwtClient) FetchAllTokens() error {

	for user, userCred := range c.users {
		token, err := c.fetchToken(userCred)
		if err != nil {
			return err
		}
		c.tokens[user] = token
	}
	return nil
}

func (c *jwtClient) FetchTokenForUser(username string) ([]byte, error) {

	userCred, ok := c.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	token, err := c.fetchToken(userCred)
	if err != nil {
		return nil, err
	}
	c.tokens[username] = token
	return token, nil
}

func (c *jwtClient) fetchToken(userCred *types.UserCred) ([]byte, error) {

	var err error

	jwtUrl := clients.ResolvePath(c.BaseURL, "token")
	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(userCred)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest("POST", jwtUrl, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/jwt")

	if c.HTTPClient == nil {
		return nil, errors.New("jwtClient.fetchToken: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPFetchJWTToken.RetCode = rsp.StatusCode
		return nil, ErrHTTPFetchJWTToken
	}
	jwtToken, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return jwtToken, nil
}
