/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/domain"
	jwtauth "github.com/intel-secl/intel-secl/v3/pkg/lib/common/jwt"
)

func SetJwtTokenRoutes(r *mux.Router, db domain.AASDatabase, tokFactory *jwtauth.JwtFactory) *mux.Router {
	defaultLog.Trace("router/jwt_certificate:SetJwtTokenRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetJwtTokenRoutes() Leaving")

	controller := controllers.JwtTokenController{
		Database:     db,
		TokenFactory: tokFactory,
	}
	r.Handle("/token", ErrorHandler(ResponseHandler(controller.CreateJwtToken, "application/jwt"))).Methods("POST")
	return r
}

func SetAuthJwtTokenRoutes(r *mux.Router, db domain.AASDatabase, tokFactory *jwtauth.JwtFactory) *mux.Router {
	defaultLog.Trace("router/jwt_certificate:SetAuthJwtTokenRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetAuthJwtTokenRoutes() Leaving")

	controller := controllers.JwtTokenController{
		Database:     db,
		TokenFactory: tokFactory,
	}
	r.Handle("/custom-claims-token", ErrorHandler(permissionsHandler(ResponseHandler(controller.CreateCustomClaimsJwtToken,
		"application/jwt"), []string{consts.CustomClaimsCreate}))).Methods("POST")

	return r
}
