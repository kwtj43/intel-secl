/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	cmw "github.com/intel-secl/intel-secl/v3/pkg/lib/common/middleware"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type Router struct {
	cfg *config.Configuration
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration, keyConfig domain.KeyControllerConfig, keyManager keymanager.KeyManager) *mux.Router {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	// ISECL-8715 - Prevent potential open redirects to external URLs
	router.SkipClean(true)

	// Define sub routes for path /kbs/v1
	defineSubRoutes(router, "/"+strings.ToLower(constants.ServiceName)+constants.ApiVersion, cfg, keyConfig, keyManager)

	// Define sub routes for path /v1
	defineSubRoutes(router, constants.ApiVersion, cfg, keyConfig, keyManager)

	return router
}

func defineSubRoutes(router *mux.Router, serviceApi string, cfg *config.Configuration, keyConfig domain.KeyControllerConfig, keyManager keymanager.KeyManager) {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = setVersionRoutes(subRouter)
	subRouter = setKeyTransferRoutes(subRouter, cfg.EndpointURL, keyConfig, keyManager)
	subRouter = setSKCKeyTransferRoutes(subRouter, cfg, keyManager)
	subRouter = setSessionRoutes(subRouter, cfg)
	subRouter = router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{cfg: cfg}
	var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)

	subRouter.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCaCertsDir, cfgRouter.fnGetJwtCerts,
		cacheTime))
	subRouter = setKeyRoutes(subRouter, cfg.EndpointURL, keyConfig, keyManager)
	subRouter = setKeyTransferPolicyRoutes(subRouter)
	subRouter = setSamlCertRoutes(subRouter)
	subRouter = setTpmIdentityCertRoutes(subRouter)
}

// Fetch JWT certificate from AAS
func (router *Router) fnGetJwtCerts() error {
	defaultLog.Trace("router/router:fnGetJwtCerts() Entering")
	defer defaultLog.Trace("router/router:fnGetJwtCerts() Leaving")

	cfg := router.cfg
	if !strings.HasSuffix(cfg.AASApiUrl, "/") {
		cfg.AASApiUrl = cfg.AASApiUrl + "/"
	}
	url := cfg.AASApiUrl + "jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Unable to create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCaCertsDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Unable to read root CA certificate")
	}

	// Get the SystemCertPool to continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if rootCAs == nil || err != nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Read body filed failed")
	}
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}
