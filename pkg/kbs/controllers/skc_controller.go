/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keytransfer"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"

	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type SKCController struct {
	remoteManager    *keymanager.RemoteManager
	policyStore      domain.KeyTransferPolicyStore
	config           *config.Configuration
	trustedCaCertDir string
}

func NewSKCController(rm *keymanager.RemoteManager, ps domain.KeyTransferPolicyStore, kc *config.Configuration, caCertDir string) *SKCController {
	return &SKCController{
		remoteManager:    rm,
		policyStore:      ps,
		config:           kc,
		trustedCaCertDir: caCertDir,
	}
}

func (kc *SKCController) TransferApplicationKey(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/skc_controller:TransferApplicationKey() Entering")
	defer defaultLog.Trace("controllers/skc_controller:TransferApplicationKey() Leaving")

	stmChallenge, sessionId, err := validateKeyTransferRequest(request.Header)
	if err != nil {
		secLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() Invalid transfer request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Transfer request is invalid"}
	}

	keyID := uuid.MustParse(mux.Vars(request)["id"])

	keyInfo := keytransfer.GetKeyInfo()

	keyInfo.PopulateStmLabels(stmChallenge, kc.config.Skc.StmLabel)

	if len(keyInfo.FinalStmLabels) == 0 {
		secLog.Errorf("controllers/skc_controller:TransferApplicationKey() %s :Stm module requested by skc_library not supported by kbs", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Stm module requested by skc_library not supported by kbs"}
	}

	if len(sessionId) != 0 {
		keyInfo.PopulateSessionId(sessionId)
	}

	keyInfo.IssuerCommonName = request.TLS.PeerCertificates[0].Issuer.CommonName
	userCommonName := request.TLS.PeerCertificates[0].Subject.CommonName

	err = keyInfo.SetUserContext(userCommonName, kc.config, kc.trustedCaCertDir)
	if err != nil {
		secLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() error while getting common name")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Couldn't fetch common name for specified user"}
	}

	key, err := kc.remoteManager.RetrieveKey(keyID)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/skc_controller:TransferApplicationKey() Key with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() Key retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key"}
		}
	}
	transferPolicy, err := kc.policyStore.Retrieve(key.TransferPolicyID)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/skc_controller:TransferApplicationKey() specified transfer policy id could not be located")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "specified transfer policy id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() Key transfer policy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key transfer policy"}
		}
	}
	keyInfo.TransferPolicyAttributes = transferPolicy

	isValidClient := keyInfo.IsValidClient()
	if !isValidClient {
		secLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() client is not valid")
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "client is not valid"}
	}

	if len(sessionId) == 0 {
		challenge, err := keyInfo.BuildChallengeJsonRequest(kc.config)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/skc_controller:TransferApplicationKey() Failed to generate challenge")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in building the challenge request"}
		} else if !(reflect.DeepEqual(challenge, kbs.ChallengeRequest{})) {
			var t kbs.Fault ///if session is  not valid then NOt Authorized.
			t.Type = "not-authorized"
			challenge.Faults = append(challenge.Faults, t)
			challenge.Operation = constants.KeyTransferOpertaion
			challenge.Status = constants.FailureStatus

			secLog.Info("controllers/skc_controller:TransferApplicationKey() Unauthorized: Generated Challenge")
			return challenge, http.StatusUnauthorized, nil
		}
	}

	///check for return value also.
	isValidSession, isValidSGXAttributes, isSessionActive := keyInfo.IsValidSession(stmChallenge)
	if isValidSession {
		if !isSessionActive {
			secLog.Info("controllers/skc_controller:TransferApplicationKey() SessionExpired: Session is expired.Hence key transfer unsuccessful.")
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Session is expired. Create new."}
		}
		if !isValidSGXAttributes {
			var challenge kbs.NotFoundResponse ///if session is valid but sgx attributes incorrect then Not Found
			var t kbs.Fault
			t.Message = "sgx attributes verification failed"
			t.Type = "not-found"
			challenge.Faults = append(challenge.Faults, t)
			challenge.Operation = constants.KeyTransferOpertaion
			challenge.Status = constants.FailureStatus

			secLog.Info("controllers/skc_controller:TransferApplicationKey() NotFound: sgx attributes verification failed")
			return challenge, http.StatusNotFound, nil
		}

		defaultLog.Debug("Session is valid. Hence directly transfer the key")
		keyData, err := kc.remoteManager.TransferKey(keyID)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/skc_controller:TransferApplicationKey() Key retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key"}
		}
		applicationKey, err := keyInfo.FetchApplicationKey(keyData, key.KeyInformation.Algorithm)
		if err != nil {
			secLog.WithError(err).WithField("id", keyID).Error(
				"controllers/skc_controller:TransferApplicationKey() Failed to fetch the application key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in fetching the application key"}
		}

		url := kc.config.EndpointURL + "/key-transfer-policies/" + key.TransferPolicyID.String()
		var outputKeyData kbs.KeyTransferResponse
		outputKeyData.KeyInfo.KeyAlgorithm = key.KeyInformation.Algorithm
		outputKeyData.KeyInfo.CreatedAt = &key.CreatedAt
		outputKeyData.KeyInfo.KeyId = keyID
		outputKeyData.KeyInfo.KeyData = applicationKey
		outputKeyData.KeyInfo.KeyLength = key.KeyInformation.KeyLength
		outputKeyData.KeyInfo.Policy.Link.KeyTransfer.Href = url
		outputKeyData.KeyInfo.Policy.Link.KeyTransfer.Method = "get"
		outputKeyData.Operation = constants.KeyTransferOpertaion
		outputKeyData.Status = constants.SuccessStatus

		sessionID, err := base64.StdEncoding.DecodeString(keyInfo.ActiveSessionID)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/skc_controller:TransferApplicationKey() Failed to decode the active session id")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error in decoding the active session id"}
		}
		sessionIDStr := fmt.Sprintf("%s:%s", keyInfo.ActiveStmLabel, sessionID)
		responseWriter.Header().Add("Session-Id", sessionIDStr)
		secLog.WithField("Key", keyID).Infof("controllers/skc_controller:TransferApplicationKey(): Successfully transferred the key: %s", request.RemoteAddr)
		delete(keyInfo.SessionIDMap, keyInfo.ActiveStmLabel+keyInfo.ActiveSessionID)
		return outputKeyData, http.StatusOK, nil
	}
	return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in transferring the application key"}
}

func validateKeyTransferRequest(header http.Header) (string, string, error) {
	defaultLog.Trace("controllers/skc_controller:validateKeyTransferRequest() Entering")
	defer defaultLog.Trace("controllers/skc_controller:validateKeyTransferRequest() Leaving")

	acceptChallenge := header.Get("Accept-Challenge")

	if len(acceptChallenge) == 0 {
		return "", "", errors.New("Accept-Challenge cannot be empty")
	}

	sessionID := header.Get("Session-Id")
	return acceptChallenge, sessionID, nil
}
