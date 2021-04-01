/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keytransfer"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KeyController struct {
	remoteManager *keymanager.RemoteManager
	policyStore   domain.KeyTransferPolicyStore
	config        domain.KeyControllerConfig
}

func NewKeyController(rm *keymanager.RemoteManager, ps domain.KeyTransferPolicyStore, kc domain.KeyControllerConfig) *KeyController {
	return &KeyController{
		remoteManager: rm,
		policyStore:   ps,
		config:        kc,
	}
}

var keySearchParams = map[string]bool{"algorithm": true, "keyLength": true, "curveType": true, "transferPolicyId": true}
var allowedAlgorithms = map[string]bool{"AES": true, "RSA": true, "EC": true, "aes": true, "rsa": true, "ec": true}
var allowedCurveTypes = map[string]bool{"secp256r1": true, "secp384r1": true, "secp521r1": true, "prime256v1": true}
var allowedKeyLengths = map[int]bool{128: true, 192: true, 256: true, 2048: true, 3072: true, 4096: true, 7680: true, 15360: true}

//Create : Function to create key
func (kc KeyController) Create(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:Create() Entering")
	defer defaultLog.Trace("controllers/key_controller:Create() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/key_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var requestKey kbs.KeyRequest
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&requestKey)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:Create() %s : Failed to decode request body as KeyRequest", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateKeyCreateRequest(requestKey)
	if err != nil {
		secLog.WithError(err).Error("controllers/key_controller:Create() Invalid create request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if requestKey.TransferPolicyID == uuid.Nil {
		defaultLog.Debug("controllers/key_controller:Create() TransferPolicy ID is not provided : Proceeding with DefaultTransferPolicy")
		requestKey.TransferPolicyID = kc.config.DefaultTransferPolicyId
	} else {
		transferPolicy, err := kc.policyStore.Retrieve(requestKey.TransferPolicyID)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/key_controller:Create() Key transfer policy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key transfer policy"}
		}

		if transferPolicy == nil {
			defaultLog.Errorf("controllers/key_controller:Create() Key transfer policy with specified id could not be located")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Key transfer policy with specified id does not exist"}
		}
	}

	privileges, err := comctx.GetUserPermissions(request)
	if err != nil {
		secLog.Errorf("controllers/key_controller:Create() %s", commLogMsg.AuthenticationFailed)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Could not get user permissions from http context"}
	}

	var createdKey *kbs.KeyResponse
	if requestKey.KeyInformation.KeyString == "" && requestKey.KeyInformation.KmipKeyID == "" {

		if !checkValidKeyPermission(privileges, []string{consts.KeyCreate}) {
			secLog.Errorf("controllers/key_controller:Create() %s", commLogMsg.UnauthorizedAccess)
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v1/keys"}
		}

		defaultLog.Debug("controllers/key_controller:Create() Create key request received")
		createdKey, err = kc.remoteManager.CreateKey(&requestKey)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/key_controller:Create() Key create failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create key"}
		}

		secLog.WithField("Id", createdKey.KeyInformation.ID).Infof("controllers/key_controller:Create() %s: Key created by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	} else {

		if !checkValidKeyPermission(privileges, []string{consts.KeyRegister}) {
			secLog.Errorf("controllers/key_controller:Create() %s", commLogMsg.UnauthorizedAccess)
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v1/keys"}
		}

		defaultLog.Debug("controllers/key_controller:Create() Register key request received")
		createdKey, err = kc.remoteManager.RegisterKey(&requestKey)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/key_controller:Create() Key register failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to register key"}
		}

		secLog.WithField("Id", createdKey.KeyInformation.ID).Infof("controllers/key_controller:Create() %s: Key registered by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	}

	return createdKey, http.StatusCreated, nil
}

//Retrieve : Function to retrieve key
func (kc KeyController) Retrieve(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/key_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	key, err := kc.remoteManager.RetrieveKey(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/key_controller:Retrieve() Key with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_controller:Retrieve() Key retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/key_controller:Retrieve() Key Retrieved by: %s", request.RemoteAddr)
	return key, http.StatusOK, nil
}

//Delete : Function to delete key
func (kc KeyController) Delete(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/key_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	err := kc.remoteManager.DeleteKey(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/key_controller:Delete() Key with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_controller:Delete() Key delete failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete key"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/key_controller:Delete() Key deleted by: %s", request.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

//Search : Function to search keys
func (kc KeyController) Search(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:Search() Entering")
	defer defaultLog.Trace("controllers/key_controller:Search() Leaving")

	// check for query parameters
	if err := utils.ValidateQueryParams(request.URL.Query(), keySearchParams); err != nil {
		secLog.Errorf("controllers/key_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	defaultLog.WithField("query", request.URL.Query()).Trace("query keys")
	criteria, err := getKeyFilterCriteria(request.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:Search() %s Invalid filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria"}
	}

	keys, err := kc.remoteManager.SearchKeys(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_controller:Search() Key search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search keys"}
	}

	secLog.Infof("controllers/key_controller:Search() %s: Keys searched by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return keys, http.StatusOK, nil
}

//Transfer : Function to perform key transfer with public key
func (kc KeyController) Transfer(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:Transfer() Entering")
	defer defaultLog.Trace("controllers/key_controller:Transfer() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypePlain {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/key_controller:Transfer() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	// Decode the incoming json data to note struct
	bytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:Transfer() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
	}

	// Decode public key in request
	key, err := crypt.GetPublicKeyFromPem(bytes)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:Transfer() %s : Public key decode failed", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to decode public key"}
	}
	envelopeKey := key.(*rsa.PublicKey)

	// Wrap key with public key
	id := uuid.MustParse(mux.Vars(request)["id"])
	wrappedKey, status, err := kc.wrapSecretKey(id, envelopeKey, sha512.New384(), nil)
	if err != nil {
		return nil, status, err
	}

	transferKeyResponse := kbs.KeyTransferAttributes{
		KeyId:   id,
		KeyData: base64.StdEncoding.EncodeToString(wrappedKey.([]byte)),
	}

	secLog.WithField("Id", id).Infof("controllers/key_controller:Transfer() %s: Key transferred using Envelope key by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return transferKeyResponse, http.StatusOK, nil
}

//TransferWithSaml : Function to perform key transfer with saml report
func (kc KeyController) TransferWithSaml(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:TransferWithSaml() Entering")
	defer defaultLog.Trace("controllers/key_controller:TransferWithSaml() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypeSaml {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/key_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	// Decode the incoming json data to note struct
	bytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:TransferWithSaml() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
	}

	// Unmarshal saml report in request
	var samlReport *saml.Saml
	err = xml.Unmarshal(bytes, &samlReport)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_controller:TransferWithSaml() %s : Saml report unmarshal failed", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to unmarshal saml report"}
	}

	// Validate saml report in request
	id := uuid.MustParse(mux.Vars(request)["id"])
	trusted, bindingCert := keytransfer.IsTrustedByHvs(string(bytes), samlReport, id, kc.config, kc.remoteManager)
	if !trusted {
		secLog.Error("controllers/key_controller:TransferWithSaml() Saml report is not trusted")
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Client not trusted by Hvs"}
	}
	envelopeKey := bindingCert.PublicKey.(*rsa.PublicKey)

	// Wrap key with binding key
	wrappedKey, status, err := kc.wrapSecretKey(id, envelopeKey, sha256.New(), []byte("TPM2\000"))
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("Id", id).Infof("controllers/key_controller:TransferWithSaml() %s: Key transferred using saml report by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return wrappedKey, http.StatusOK, nil
}

func (kc KeyController) wrapSecretKey(id uuid.UUID, publicKey *rsa.PublicKey, hash hash.Hash, label []byte) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_controller:wrapSecretKey() Entering")
	defer defaultLog.Trace("controllers/key_controller:wrapSecretKey() Leaving")

	secretKey, err := kc.remoteManager.TransferKey(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/key_controller:wrapSecretKey() Key with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_controller:wrapSecretKey() Key transfer failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to transfer Key"}
		}
	}

	// Wrap secret key with public key
	wrappedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, secretKey, label)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_controller:wrapSecretKey() Wrap key failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to wrap key"}
	}

	return wrappedKey, http.StatusOK, nil
}

//validateKeyCreateRequest checks for various attributes in the Key Create request and returns a boolean value
func validateKeyCreateRequest(requestKey kbs.KeyRequest) error {
	defaultLog.Trace("controllers/key_controller:validateKeyCreateRequest() Entering")
	defer defaultLog.Trace("controllers/key_controller:validateKeyCreateRequest() Leaving")

	algorithm := requestKey.KeyInformation.Algorithm
	if algorithm == "" {
		return errors.New("key algorithm is missing")
	} else if !allowedAlgorithms[algorithm] {
		return errors.New("key algorithm is not supported")
	}

	if strings.ToUpper(algorithm) == consts.CRYPTOALG_EC {
		if requestKey.KeyInformation.CurveType == "" {
			return errors.New("curve_type must be provided")
		} else if !allowedCurveTypes[requestKey.KeyInformation.CurveType] {
			return errors.New("curve_type is not supported")
		}
	} else {
		if requestKey.KeyInformation.KeyLength == 0 {
			return errors.New("Key length is missing")
		} else if !allowedKeyLengths[requestKey.KeyInformation.KeyLength] {
			return errors.New("key_length is not supported")
		}
	}

	keyString := requestKey.KeyInformation.KeyString
	kmipKeyID := requestKey.KeyInformation.KmipKeyID
	if keyString != "" {
		if err := validation.ValidatePemEncodedKey(keyString); err != nil {
			return errors.New("key_string must be PEM formatted")
		}
	} else if kmipKeyID != "" {
		if err := validation.ValidateStrings([]string{kmipKeyID}); err != nil {
			return errors.New("kmip_key_id must be a valid string")
		}
	}

	if requestKey.Label != "" {
		if err := validation.ValidateTextString(requestKey.Label); err != nil {
			return errors.New("valid contents for label must be specified")
		}
	}

	if requestKey.Usage != "" {
		if err := validation.ValidateTextString(requestKey.Usage); err != nil {
			return errors.New("valid contents for usage must be specified")
		}
	}

	return nil
}

//getKeyFilterCriteria checks for set filter params in the Search request and returns a valid KeyFilterCriteria
func getKeyFilterCriteria(params url.Values) (*models.KeyFilterCriteria, error) {
	defaultLog.Trace("controllers/key_controller:getKeyFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/key_controller:getKeyFilterCriteria() Leaving")

	criteria := models.KeyFilterCriteria{}

	// algorithm
	if param := strings.TrimSpace(params.Get("algorithm")); param != "" {
		if !allowedAlgorithms[param] {
			return nil, errors.New("Valid algorithm must be specified")
		}
		criteria.Algorithm = param
	}

	// keyLength
	if param := strings.TrimSpace(params.Get("keyLength")); param != "" {
		length, err := strconv.Atoi(param)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid keyLength query param value, must be Integer")
		}
		if !allowedKeyLengths[length] {
			return nil, errors.New("Valid keyLength must be specified")
		}
		criteria.KeyLength = length
	}

	// curveType
	if param := strings.TrimSpace(params.Get("curveType")); param != "" {
		if !allowedCurveTypes[param] {
			return nil, errors.New("Valid curveType must be specified")
		}
		criteria.CurveType = param
	}

	// transferPolicyId
	if param := strings.TrimSpace(params.Get("transferPolicyId")); param != "" {
		id, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid transferPolicyId query param value, must be UUID")
		}
		criteria.TransferPolicyId = id
	}

	return &criteria, nil
}

func checkValidKeyPermission(privileges []ct.PermissionInfo, requiredPermission []string) bool {
	defaultLog.Trace("controllers/key_controller:checkValidKeyPermission() Entering")
	defer defaultLog.Trace("controllers/key_controller:checkValidKeyPermission() Leaving")
	reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: requiredPermission}
	_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
		true)
	if !foundMatchingPermission {
		secLog.Errorf("controllers/key_controller:checkValidKeyPermission() %s Insufficient privileges to access /v1/keys", commLogMsg.UnauthorizedAccess)
		return false
	}
	return true
}
