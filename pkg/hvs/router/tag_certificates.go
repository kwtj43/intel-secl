/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	hostConnector "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
)

const (
	TagCertificateEndpointPath       = "/tag-certificates"
	TagCertificateDeployEndpointPath = "/rpc/deploy-tag-certificate"
)

// SetTagCertificateRoutes registers routes for tag-certificates API
func SetTagCertificateRoutes(router *mux.Router, cfg *config.Configuration, flavorGroupStore *postgres.FlavorGroupStore, certStore *models.CertificatesStore, hostTrustManager domain.HostTrustManager, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/tag_certificates:SetTagCertificateRoutes() Entering")
	defer defaultLog.Trace("router/tag_certificates:SetTagCertificateRoutes() Leaving")

	// set up the HostConnectorProvider for the Controller
	rootCAs := (*certStore)[models.CaCertTypesRootCa.String()].Certificates
	var hcp hostConnector.HostConnectorProvider
	hcp = hostConnector.NewHostConnectorFactory(cfg.AASApiUrl, rootCAs, cfg.NATS.Servers)

	if hcp == nil {
		defaultLog.Errorf("router/tag_certificates:SetTagCertificateRoutes() %s : Error initializing the Host Connector Factory", commLogMsg.AppRuntimeErr)
		return nil
	}

	tagCertificateStore := postgres.NewTagCertificateStore(store)
	hostStore := postgres.NewHostStore(store)
	flavorStore := postgres.NewFlavorStore(store)

	// initialize the user credentials for AAS connections
	tcConfig := domain.TagCertControllerConfig{
		AASApiUrl:       cfg.AASApiUrl,
		ServiceUsername: cfg.HVS.Username,
		ServicePassword: cfg.HVS.Password,
	}

	tagCertificateController := controllers.NewTagCertificateController(tcConfig, *certStore, tagCertificateStore, hostTrustManager, hostStore,
		flavorStore, flavorGroupStore, hcp)
	if tagCertificateController != nil {
		tagCertificateIdExpr := fmt.Sprintf("%s%s", TagCertificateEndpointPath+"/", validation.IdReg)
		router.Handle(TagCertificateEndpointPath,
			ErrorHandler(permissionsHandler(JsonResponseHandler(tagCertificateController.Create),
				[]string{constants.TagCertificateCreate}))).Methods("POST")

		router.Handle(TagCertificateEndpointPath,
			ErrorHandler(permissionsHandler(JsonResponseHandler(tagCertificateController.Search),
				[]string{constants.TagCertificateSearch}))).Methods("GET")

		router.Handle(tagCertificateIdExpr,
			ErrorHandler(permissionsHandler(ResponseHandler(tagCertificateController.Delete),
				[]string{constants.TagCertificateDelete}))).Methods("DELETE")

		router.Handle(TagCertificateDeployEndpointPath,
			ErrorHandler(permissionsHandler(JsonResponseHandler(tagCertificateController.Deploy),
				[]string{constants.TagCertificateDeploy}))).Methods("POST")
	}
	return router
}
