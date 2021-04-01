/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package keytransfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	aasClient "github.com/intel-secl/intel-secl/v3/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
	"time"
)

const (
	ivSize   = 4
	tagSize  = 4
	wrapSize = 4
)

// KeyDetails - Key info for skc transfer application key
type KeyDetails struct {
	IssuerCommonName         string
	ActiveStmLabel           string
	ActiveSessionID          string
	ClientCertSHA            string
	ListOfContexts           []string
	FinalStmLabels           []string
	TransferPolicyAttributes *kbs.KeyTransferPolicyAttributes
	SessionIDMap             map[string]string
	SessionMap               map[string]kbs.KeyTransferSession
	SessionResponseMap       map[string]kbs.QuoteVerifyAttributes
}

var keyInfo *KeyDetails

var secLog = log.GetSecurityLogger()

func InitializeKeyInfo() *KeyDetails {
	defaultLog.Trace("keytransfer/skc_key_transfer:InitializeKeyInfo() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:InitializeKeyInfo() Leaving")
	keyInfo := new(KeyDetails)
	keyInfo.SessionIDMap = make(map[string]string)
	keyInfo.SessionMap = make(map[string]kbs.KeyTransferSession)
	keyInfo.SessionResponseMap = make(map[string]kbs.QuoteVerifyAttributes)
	return keyInfo
}

func GetKeyInfo() *KeyDetails {
	defaultLog.Trace("keytransfer/skc_key_transfer:GetKeyInfo() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:GetKeyInfo() Leaving")
	if keyInfo == nil {
		keyInfo = InitializeKeyInfo()
	}
	return keyInfo
}

// iterate throuh the slice and append only if value is not present
func appendIfUnique(slice []string, element string) []string {
	for _, sliceElement := range slice {
		if sliceElement == element {
			return slice
		}
	}
	return append(slice, element)
}

// this function selects common key transfer modes between kbs and skc_library
func (keyInfo *KeyDetails) PopulateStmLabels(acceptChallenge, stmLabel string) {
	defaultLog.Trace("keytransfer/skc_key_transfer:Populatestmlabels() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:Populatestmlabels() leaving")

	// start with nil list for negotiated key transfer mode between kbs and skc_library
	keyInfo.FinalStmLabels = nil

	var labels, requestedStmLabels []string
	if strings.Contains(stmLabel, ",") {
		labels = strings.Split(stmLabel, ",")
	} else {
		labels = appendIfUnique(labels, stmLabel)
	}

	if strings.Contains(acceptChallenge, ",") {
		requestedStmLabels = strings.Split(acceptChallenge, ",")
	} else {
		requestedStmLabels = appendIfUnique(requestedStmLabels, acceptChallenge)
	}

	for _, defaultStmLabel := range labels {
		for _, requestedStmLabel := range requestedStmLabels {
			if defaultStmLabel == requestedStmLabel {
				keyInfo.FinalStmLabels = appendIfUnique(keyInfo.FinalStmLabels, requestedStmLabel)
			}
		}
	}
}

func (keyInfo *KeyDetails) PopulateSessionId(sessionId string) {
	defaultLog.Trace("keytransfer/skc_key_transfer:PopulateSessionId() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:PopulateSessionId() leaving")

	var stmSessionList []string

	if strings.Contains(sessionId, ",") {
		stmSessionList = strings.Split(sessionId, ",")
	} else {
		stmSessionList = appendIfUnique(stmSessionList, sessionId)
	}

	for _, stmSessionStr := range stmSessionList {
		stmSessionIDPair := strings.Split(stmSessionStr, ":")
		stmLab := stmSessionIDPair[0]
		session := stmSessionIDPair[1]
		encSessionID := base64.StdEncoding.EncodeToString([]byte(session))
		if len(stmLab) != 0 {
			keyInfo.SessionIDMap[stmLab+encSessionID] = encSessionID
		}
	}
}

func (keyInfo *KeyDetails) SetUserContext(userCommonName string, cfg *config.Configuration, caCertDir string) error {
	defaultLog.Trace("keytransfer/skc_key_transfer:SetUserContext() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:SetUserContext() leaving")

	caCerts, err := crypt.GetCertsFromDir(caCertDir)
	if err != nil {
		defaultLog.WithError(err).Errorf("keytransfer/skc_key_transfer:SetUserContext() Error while getting certs from %s", constants.TrustedCaCertsDir)
		return err
	}

	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		defaultLog.WithError(err).Error("keytransfer/skc_key_transfer:SetUserContext() Error while creating http client")
		return err
	}

	jwtcl := aasClient.NewJWTClient(cfg.AASApiUrl)
	jwtcl.HTTPClient = client
	tokenBytes, err := jwtcl.GetUserToken(cfg.KBS.UserName)
	if err != nil {
		jwtcl.AddUser(cfg.KBS.UserName, cfg.KBS.Password)
		tokenBytes, err = jwtcl.FetchTokenForUser(cfg.KBS.UserName)
		if err != nil {
			defaultLog.WithError(err).Error("keytransfer/skc_key_transfer:SetUserContext() Could not fetch token for user " + cfg.KBS.UserName)
			return errors.New("Could not fetch token for user " + cfg.KBS.UserName)
		}
	}

	aasClient := aasClient.Client{
		BaseURL:    cfg.AASApiUrl,
		JWTToken:   tokenBytes,
		HTTPClient: client,
	}

	userDetails, err := aasClient.GetUsers(userCommonName)
	if err != nil {
		secLog.WithError(err).Errorf("keytransfer/skc_key_transfer:SetUserContext() Error while getting user details from AAS")
		return err
	}
	userRoles, err := aasClient.GetRolesForUser(userDetails[0].ID)
	if err != nil {
		secLog.WithError(err).Errorf("keytransfer/skc_key_transfer:SetUserContext() Error while getting roles details from AAS")
		return err
	}

	for _, roles := range userRoles {
		if roles.Service == constants.ServiceName && roles.Name == constants.TransferRoleType {
			context := roles.Context

			matched, err := regexp.Match(constants.ContextPermissionsRegex, []byte(context))
			if err != nil {
				secLog.WithError(err).Errorf("keytransfer/skc_key_transfer:SetUserContext() %s : Context list in workload role does not match that of key transfer policy", commLogMsg.InvalidInputBadParam)
				return err
			}

			if matched {
				contextList := strings.Split(context, "=")
				contextArr := strings.Split(contextList[1], ",")
				keyInfo.ListOfContexts = contextArr
			}
			break
		}
	}

	return nil
}

func (keyInfo *KeyDetails) IsValidClient() bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:IsValidClient() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:IsValidClient() leaving")
	if keyInfo.doesCertIssuerCNMatchKeyTransferPolicy() &&
		keyInfo.doesAttestTypeMatchKeyTransferPolicy() &&
		keyInfo.doesCertcontextListMatchKeyTransferPolicy() {
		return true
	}
	return false
}

// doesCertIssuerCNMatchKeyTransferPolicy - Function to check common name of certificate issuer matches with KeyTransferPolicy
func (keyInfo KeyDetails) doesCertIssuerCNMatchKeyTransferPolicy() bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:doesCertIssuerCNMatchKeyTransferPolicy() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:doesCertIssuerCNMatchKeyTransferPolicy() Leaving")

	commonNamesList := keyInfo.TransferPolicyAttributes.TLSClientCertificateIssuerCNAnyof
	for _, commonName := range commonNamesList {
		if commonName == keyInfo.IssuerCommonName {
			defaultLog.Debug("keytransfer/skc_key_transfer:doesCertIssuerCNMatchKeyTransferPolicy() Issuer common name in workload certificate matches with the key transfer policy")
			return true
		}
	}
	return false
}

// doesAttestTypeMatchKeyTransferPolicy - Function to check attest type matches with KeyTransferPolicy
func (keyInfo *KeyDetails) doesAttestTypeMatchKeyTransferPolicy() bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:doesAttestTypeMatchKeyTransferPolicy() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:doesAttestTypeMatchKeyTransferPolicy() Leaving")

	attestationType := keyInfo.TransferPolicyAttributes.AttestationTypeAnyof
	if attestationType == nil {
		defaultLog.Error("keytransfer/skc_key_transfer:doesAttestTypeMatchKeyTransferPolicy()  attestation type is empty.")
		return false
	}

	var stmLabels []string
	if len(keyInfo.FinalStmLabels) > 1 {
		for _, stmLabel := range keyInfo.FinalStmLabels {
			for _, attestType := range attestationType {
				if stmLabel == attestType {
					stmLabels = append(stmLabels, attestType)
				}
			}
		}
		if len(stmLabels) == 0 {
			defaultLog.Debug("keytransfer/skc_key_transfer_key:doesAttestTypeMatchKeyTransferPolicy() Stm label in request does not match with key transfer policy")
			return false
		} else {
			defaultLog.Debug("keytransfer/skc_key_transfer:doesAttestTypeMatchKeyTransferPolicy() Stm label (attestation type) matches with the key transfer policy")
			keyInfo.ActiveStmLabel = prioritizeStmLabels(stmLabels)
			return true
		}
	} else {
		for _, attType := range attestationType {
			if attType == keyInfo.FinalStmLabels[0] {
				keyInfo.ActiveStmLabel = keyInfo.FinalStmLabels[0]
				return true
			}
		}
	}
	return false
}

// prioritizeStmLabels - Function to prioritize stm labels
func prioritizeStmLabels(stmLabels []string) string {
	defaultLog.Trace("keytransfer/skc_key_transfer:prioritizeStmLabels() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:prioritizeStmLabels() Leaving")

	for _, label := range stmLabels {
		if label == constants.DefaultSGXLabel {
			return constants.DefaultSGXLabel
		}
	}
	return constants.DefaultSWLabel
}

// doesCertcontextListMatchKeyTransferPolicy - Function to check context list matches with KeyTransferPoilcy
func (keyInfo KeyDetails) doesCertcontextListMatchKeyTransferPolicy() bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() Leaving")

	if keyInfo.ListOfContexts == nil {
		defaultLog.Error("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() Context list is empty.")
		return false
	}

	clientCertContextAnyOf := keyInfo.TransferPolicyAttributes.TLSClientCertificateSANAnyof
	clientCertContextAllOf := keyInfo.TransferPolicyAttributes.TLSClientCertificateSANAllof

	if len(clientCertContextAnyOf) > 0 {
		for _, context := range keyInfo.ListOfContexts {
			for _, contextFromTransferPolicy := range keyInfo.TransferPolicyAttributes.TLSClientCertificateSANAnyof {
				if context == contextFromTransferPolicy {
					defaultLog.Debug("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() Context in workload certificate matches with the key transfer policy")
					return true
				}
			}
		}
	} else if len(clientCertContextAllOf) > 0 {
		if len(clientCertContextAllOf) == len(keyInfo.ListOfContexts) {
			sort.Strings(clientCertContextAllOf)
			sort.Strings(keyInfo.ListOfContexts)
			if reflect.DeepEqual(clientCertContextAllOf, keyInfo.ListOfContexts) {
				return true
			} else {
				defaultLog.Error("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() clientCertContextAllOf doesn't match context list")
				return false
			}
		} else if len(clientCertContextAllOf) > len(keyInfo.ListOfContexts) {
			defaultLog.Error("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() clientCertContextAllOf list can't be greater than context list")
			return false
		} else {
			value := false
			for i := 0; i < len(clientCertContextAllOf); i++ {
				for _, v := range keyInfo.ListOfContexts {
					if v == clientCertContextAllOf[i] {
						value = true
						break
					} else {
						value = false
					}
				}
			}
			if value == true {
				return true
			} else {
				defaultLog.Error("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() clientCertContextAllOf is not in context list")
				return false
			}
		}
	} else {
		defaultLog.Error("keytransfer/skc_key_transfer:doesCertcontextListMatchKeyTransferPolicy() workload role contains Context info, but missing in key transfer policy")
	}
	return false
}

func (keyInfo *KeyDetails) IsValidSession(stmLabel string) (validSession, validSGXAttributes, activeSession bool) {
	defaultLog.Trace("keytransfer/skc_key_transfer:IsValidSession() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:IsValidSession() leaving")

	var sessionID string
	sessionFound := false
	for _, value := range keyInfo.SessionIDMap {
		sessionID = value
		_, session := keyInfo.SessionMap[sessionID]
		// ensure that session id and the stmlabel in key transfer request
		// are the same as in session map
		if session && keyInfo.SessionMap[sessionID].Stmlabel == stmLabel {
			sessionFound = true

			expiryTime := keyInfo.SessionMap[sessionID].SessionExpiryTime

			if expiryTime.Before(time.Now()) {
				defaultLog.Debug("session has expired hence exiting")
				///delete session from map
				delete(keyInfo.SessionMap, sessionID)
				return true, true, false
			}
			break
		}
	}

	if sessionFound {
		keyTransferSession := keyInfo.GetSessionObj(sessionID)
		if keyInfo.ClientCertSHA == keyTransferSession.ClientCertHash {
			if keyInfo.ActiveStmLabel == constants.DefaultSGXLabel {
				attributes := keyInfo.SessionResponseMap[sessionID]
				if keyInfo.TransferPolicyAttributes.SGXEnforceTCBUptoDate && attributes.TCBLevel == constants.TCBLevelOutOfDate {
					defaultLog.Debug("keytransfer/skc_key_transfer:IsValidSession() Platform TCB Status is Out of Date")
					return true, false, true
				}

				if keyInfo.validateSgxEnclaveIssuer(attributes.EnclaveIssuer) &&
					keyInfo.validateSgxEnclaveIssuerProdId(attributes.EnclaveIssuerProductID) &&
					keyInfo.validateSgxEnclaveIssuerExtProdId(attributes.EnclaveIssuerExtendedProductID) &&
					keyInfo.validateSgxEnclaveMeasurement(attributes.EnclaveMeasurement) &&
					keyInfo.validateSgxConfigId(attributes.ConfigID) &&
					keyInfo.validateSgxIsvSvn(attributes.IsvSvn) &&
					keyInfo.validateSgxConfigIdSvn(attributes.ConfigSvn) {
					keyInfo.ActiveSessionID = sessionID
					defaultLog.Debug("keytransfer/skc_key_transfer:IsValidSession() All sgx attributes in stm attestation report match key transfer policy")
					return true, true, true
				} else {
					///delete session from map
					delete(keyInfo.SessionMap, sessionID)
					defaultLog.Debug("keytransfer/skc_key_transfer:IsValidSession() Sgx attribute validation failed")
					return true, false, true
				}

			} else {
				keyInfo.ActiveSessionID = sessionID
				return true, true, true
			}
			//}
		}
	}
	return false, false, false
}

func (keyInfo *KeyDetails) deleteExpiredSessions() {

	defaultLog.Trace("keytransfer/skc_key_transfer:deleteExpiredSessions() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:deleteExpiredSessions() leaving")

	for k := range keyInfo.SessionMap {
		if keyInfo.SessionMap[k].SessionExpiryTime.Before(time.Now()) {
			delete(keyInfo.SessionMap, k)
		}
	}
}

func (keyInfo *KeyDetails) BuildChallengeJsonRequest(cfg *config.Configuration) (kbs.ChallengeRequest, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:BuildChallengeJsonRequest() entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:BuildChallengeJsonRequest() leaving")

	keyInfo.deleteExpiredSessions()

	var challengeReq kbs.ChallengeRequest

	challengeReq.ChallengeType = keyInfo.ActiveStmLabel

	challenge, err := keyInfo.generateStmChallenge(cfg.Skc.SessionExpiryTime)
	if err != nil {
		return challengeReq, errors.Wrap(err, "Failed to generate challenge")
	}
	challengeReq.Challenge = challenge
	url := cfg.EndpointURL + "/session"

	challengeReq.Link.ChallengeReply.Href = url
	challengeReq.Link.ChallengeReply.Method = "post"

	return challengeReq, nil
}

// GetSessionObj - Function to get the key transfer attributes
func (keyInfo KeyDetails) GetSessionObj(encSessionID string) kbs.KeyTransferSession {
	defaultLog.Trace("keytransfer/skc_key_transfer:GetSessionObj() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:GetSessionObj() Leaving")

	return keyInfo.SessionMap[encSessionID]
}

// validateSgxEnclaveIssuer - Function to Validate SgxEnclaveIssuer
func (keyInfo KeyDetails) validateSgxEnclaveIssuer(stmSgxEnclaveIssuer string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuer() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuer() Leaving")

	if stmSgxEnclaveIssuer == "" {
		defaultLog.Error("keytransfer/skc_key_transfer:validateSgxEnclaveIssuer() sgx_enclave_issuer missing from sgx attestation report")
		return false
	}

	for _, enclaveIssue := range keyInfo.TransferPolicyAttributes.SGXEnclaveIssuerAnyof {
		if stmSgxEnclaveIssuer == enclaveIssue {
			defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxEnclaveIssuer() StmSgxEnclaveIssuer matches with the key transfer policy")
			return true
		}
	}
	return false

}

// validateSgxEnclaveIssuerProdId - Function to Validate SgxEnclaveIssuerProdId
func (keyInfo KeyDetails) validateSgxEnclaveIssuerProdId(stmSgxEnclaveIssuerProdID string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerProdId() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerProdId() Leaving")

	if stmSgxEnclaveIssuerProdID == "" {
		defaultLog.Error("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerProdId() sgx_enclave_issuer_product_id missing from sgx attestation report")
		return false
	}
	stmSgxEnclaveIssuerProdIDIn, err := strconv.Atoi(stmSgxEnclaveIssuerProdID)
	if err != nil {
		defaultLog.Error("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerProdId() Error in converting encalve issue id")
		return false

	}
	a1 := int16(stmSgxEnclaveIssuerProdIDIn)
	for _, enclaveIssuerProdID := range keyInfo.TransferPolicyAttributes.SGXEnclaveIssuerProductIDAnyof {
		if a1 == enclaveIssuerProdID {
			defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerProdId() StmSgxEnclaveIssuerProdID matches with the key transfer policy")
			return true
		}
	}
	return false
}

// validateSgxEnclaveIssuerExtProdId - Function to Validate SgxEnclaveIssuerExtProdId
func (keyInfo KeyDetails) validateSgxEnclaveIssuerExtProdId(stmSgxEnclaveIssuerExtProdID string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerExtProdId() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerExtProdId() Leaving")

	if stmSgxEnclaveIssuerExtProdID == "" && len(keyInfo.TransferPolicyAttributes.SGXEnclaveIssuerExtendedProductIDAnyof) == 0 {
		defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerExtProdId() StmSgxEnclaveIssuerExtProdID matches with the key transfer policy")
		return true
	}

	for _, enclaveIssuerExtProdID := range keyInfo.TransferPolicyAttributes.SGXEnclaveIssuerExtendedProductIDAnyof {
		if stmSgxEnclaveIssuerExtProdID == enclaveIssuerExtProdID {
			defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxEnclaveIssuerExtProdId() StmSgxEnclaveIssuerExtProdID matches with the key transfer policy")
			return true
		}
	}
	return false
}

// validateSgxEnclaveMeasurement - Function to Validate SgxEnclaveMeasurement
func (keyInfo KeyDetails) validateSgxEnclaveMeasurement(stmSgxEnclaveMeasurement string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveMeasurement() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveMeasurement() Leaving")

	if stmSgxEnclaveMeasurement == "" && len(keyInfo.TransferPolicyAttributes.SGXEnclaveMeasurementAnyof) == 0 {
		defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxEnclaveMeasurement() StmSgxEnclaveMeasurement matches with the key transfer policy")
		return true
	}

	for _, sgxEnclaveMeasurement := range keyInfo.TransferPolicyAttributes.SGXEnclaveMeasurementAnyof {
		if stmSgxEnclaveMeasurement == sgxEnclaveMeasurement {
			defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxEnclaveMeasurement() StmSgxEnclaveMeasurement matches with the key transfer policy")
			return true
		}
	}

	return false
}

// validateSgxConfigId - Function to Validate SgxConfigId
func (keyInfo KeyDetails) validateSgxConfigId(stmSgxConfigID string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxConfigId() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxConfigId() Leaving")

	if stmSgxConfigID == "" && len(keyInfo.TransferPolicyAttributes.SGXConfigIDAnyof) == 0 {
		defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxConfigId() StmSgxConfigID matches with the key transfer policy")
		return true
	}

	for _, sgxConfigID := range keyInfo.TransferPolicyAttributes.SGXConfigIDAnyof {
		if stmSgxConfigID == sgxConfigID {
			defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxConfigId() StmSgxConfigID matches with the key transfer policy")
			return true
		}
	}
	return false
}

// validateSgxIsvSvn- Function to Validate isvSvn
func (keyInfo KeyDetails) validateSgxIsvSvn(stmSgxIsvSvn string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxIsvSvn() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxIsvSvn() Leaving")

	stmSgxsvn, err := strconv.Atoi(stmSgxIsvSvn)
	if err != nil {
		defaultLog.Error("keytransfer/skc_key_transfer:validateSgxIsvSvn() Error in converting isvSvn to integer")
		return false

	}
	a1 := int16(stmSgxsvn)
	if a1 == keyInfo.TransferPolicyAttributes.SGXEnclaveSVNMinimum {
		defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxIsvSvn() stmSgxIsvSvn matches with the key transfer policy")
		return true
	}
	return false
}

// validateSgxConfigIdSvn- Function to Validate configIdSvn
func (keyInfo KeyDetails) validateSgxConfigIdSvn(stmSgxConfigSvn string) bool {
	defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxConfigIdSvn() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:validateSgxConfigIdSvn() Leaving")

	stmSgxConfigIdSvn, err := strconv.Atoi(stmSgxConfigSvn)
	if err != nil {
		defaultLog.Error("keytransfer/skc_key_transfer:validateSgxConfigIdSvn() Error in converting stmSgxConfigIdSvn to integer")
		return false

	}
	a1 := int16(stmSgxConfigIdSvn)
	if a1 == keyInfo.TransferPolicyAttributes.SGXConfigIDSVN {
		defaultLog.Debug("keytransfer/skc_key_transfer:validateSgxConfigIdSvn() stmSgxConfigIdSvn matches with the key transfer policy")
		return true
	}
	return false
}

// generateStmChallenge - Function to generate stm challenge
func (keyInfo KeyDetails) generateStmChallenge(mins int) (string, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:generateStmChallenge() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:generateStmChallenge() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return "", errors.Wrap(err, "keytransfer/skc_key_transfer:generateStmChallenge() failed to create new UUID")
	}
	encSessionID := base64.StdEncoding.EncodeToString([]byte(newUuid.String()))

	var keytransfer kbs.KeyTransferSession
	keytransfer.SessionId = encSessionID
	keytransfer.ClientCertHash = keyInfo.ClientCertSHA
	keytransfer.Stmlabel = keyInfo.ActiveStmLabel
	keytransfer.SessionExpiryTime = time.Now().Add(time.Minute * time.Duration(mins))

	keyInfo.SessionMap[encSessionID] = keytransfer

	return encSessionID, nil
}

// FetchApplicationKey - Function to fetch the application key
func (keyInfo *KeyDetails) FetchApplicationKey(keyData []byte, algorithm string) (string, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:FetchApplicationKey() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:FetchApplicationKey() Leaving")

	var transferredKeyData string
	var err error

	switch strings.ToUpper(keyInfo.ActiveStmLabel) {
	case constants.DefaultSGXLabel:
		transferredKeyData, err = keyInfo.getKeyForSGX(keyData, algorithm)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:FetchApplicationKey() Error in getting sgx mode key")
		}
	case constants.DefaultSWLabel:
		transferredKeyData, err = keyInfo.getKeyForSW(keyData)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:FetchApplicationKey() Error in getting sw mode key")
		}
	default:
		return "", errors.New("keytransfer/skc_key_transfer:FetchApplicationKey() Invalid stm label")
	}

	return transferredKeyData, nil
}

// getKeyForSGX - Function to get key for SGX node
func (keyInfo *KeyDetails) getKeyForSGX(privateKey []byte, algorithm string) (string, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:getKeyForSGX() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:getKeyForSGX() Leaving")

	var bytes, nonceByte []byte
	var err error

	if err != nil {
		return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSGX() Failed to decode private key")
	}

	keyTransferSession := keyInfo.GetSessionObj(keyInfo.ActiveSessionID)
	if reflect.DeepEqual(keyTransferSession, kbs.KeyTransferSession{}) {
		defaultLog.Error("keytransfer/skc_key_transfer:getKeyForSGX() session map is empty. Hence can't get swk")
		return "", errors.New("keytransfer/skc_key_transfer:getKeyForSGX() session map is empty. Hence can't get swk")
	}
	swkKey := keyTransferSession.SWK

	if algorithm == constants.CRYPTOALG_AES {
		bytes, nonceByte, err = AesEncrypt(privateKey, swkKey)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSGX() Failed to encrypt data")
		}
	} else if algorithm == constants.CRYPTOALG_RSA {
		defaultLog.Trace("RSA key to be transferred")
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privateKey,
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			return "", errors.New("keytransfer/skc_key_transfer:getKeyForSGX() Failed to decode the private key")
		}
		bytes, nonceByte, err = AesEncrypt(decodedBlock.Bytes, swkKey)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSGX() Failed to encrypt data")
		}
	} else if algorithm == constants.CRYPTOALG_EC {
		///TODO: This needs to be tested.
		defaultLog.Trace("EC key to be transferred")
		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: privateKey,
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			return "", errors.New("keytransfer/skc_key_transfer:getKeyForSGX() Failed to decode the private key")
		}
		bytes, nonceByte, err = AesEncrypt(decodedBlock.Bytes, swkKey)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSGX() Failed to encrypt data")
		}
	}

	keyMetaDataSize := ivSize + tagSize + wrapSize
	ivLength := len(nonceByte)
	keyMetaData := make([]byte, keyMetaDataSize)
	binary.LittleEndian.PutUint32(keyMetaData[0:], uint32(ivLength))
	binary.LittleEndian.PutUint32(keyMetaData[4:], uint32(16))
	binary.LittleEndian.PutUint32(keyMetaData[8:], uint32(len(bytes)))

	keyData := []byte{}
	keyData = append(keyData, keyMetaData...)
	keyData = append(keyData, nonceByte...)
	keyData = append(keyData, bytes...)

	return base64.StdEncoding.EncodeToString(keyData), nil
}

// getKeyForSW - Function to get the key for SW node
func (keyInfo KeyDetails) getKeyForSW(keyBytes []byte) (string, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:getKeyForSW() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:getKeyForSW() Leaving")

	keyTransferSession := keyInfo.GetSessionObj(keyInfo.ActiveSessionID)
	if reflect.DeepEqual(keyTransferSession, kbs.KeyTransferSession{}) {
		defaultLog.Error("keytransfer/skc_key_transfer:getKeyForSW() session map is empty. Hence can't get swk")
		return "", errors.New("keytransfer/skc_key_transfer:getKeyForSW() session map is empty. Hence can't get swk")
	}

	swkKey := keyTransferSession.SWK

	var wrappedBytes []byte

	alignment := (len(keyBytes)) % 8

	if alignment != 0 {
		size := len(keyBytes) + (8 - alignment)
		paddedArr := []byte{}
		paddedArr = append(paddedArr, keyBytes...)

		paddingLength := size - len(paddedArr)
		zeroPadding := make([]byte, paddingLength)
		paddedArr = append(paddedArr, zeroPadding...)

		bytes, err := keyWrap(swkKey, paddedArr)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSW() Failed to encrypt data")
		}
		wrappedBytes = bytes
	} else {
		bytes, _, err := AesEncrypt(keyBytes, swkKey)
		if err != nil {
			return "", errors.Wrap(err, "keytransfer/skc_key_transfer:getKeyForSW() Failed to encrypt data")
		}
		wrappedBytes = bytes
	}

	ivLength := 0
	tagLength := 0

	keyMetaDataSize := ivSize + tagSize + wrapSize

	keyMetaData := make([]byte, keyMetaDataSize)
	binary.LittleEndian.PutUint32(keyMetaData[0:], uint32(ivLength))
	binary.LittleEndian.PutUint32(keyMetaData[4:], uint32(tagLength))
	binary.LittleEndian.PutUint32(keyMetaData[8:], uint32(len(wrappedBytes)))

	keyData := []byte{}
	keyData = append(keyData, keyMetaData...)
	keyData = append(keyData, wrappedBytes...)

	return base64.StdEncoding.EncodeToString(keyData), nil

}

// AesEncrypt encrypts plain bytes using AES key passed as param
func AesEncrypt(data, key []byte) ([]byte, []byte, error) {
	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal

	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// here we encrypt data using the Seal function
	return gcm.Seal(nil, nonce, data, nil), nonce, nil
}

// Wrap a key using the RFC 3394 AES Key Wrap Algorithm.
func keyWrap(wrapkey, keyBytes []byte) ([]byte, error) {
	defaultLog.Trace("keytransfer/skc_key_transfer:keyWrap() Entering")
	defer defaultLog.Trace("keytransfer/skc_key_transfer:keyWrap() Leaving")

	if len(keyBytes)%8 != 0 {
		return nil, errors.New("keytransfer/skc_key_transfer:keyWrap() Data to be wrapped not correct.")
	}

	cipher, err := aes.NewCipher(wrapkey)
	if err != nil {
		return nil, err
	}

	nblocks := len(keyBytes) / 8

	// 1) Initialize variables.
	var block [aes.BlockSize]byte
	// - Set A = IV, an initial value (see 2.2.3)
	for i := 0; i < 8; i++ {
		block[i] = 0xA6
	}

	// - For i = 1 to n
	// -   Set R[i] = P[i]
	intermediate := make([]byte, len(keyBytes))
	copy(intermediate, keyBytes)

	// 2) Calculate intermediate values.
	for i := 0; i < 6; i++ {
		for j := 0; j < nblocks; j++ {
			// - B = AES(K, A | R[i])
			copy(block[8:], intermediate[j*8:j*8+8])
			cipher.Encrypt(block[:], block[:])

			// - A = MSB(64, B) ^ t where t = (n*j)+1
			t := uint64(i*nblocks + j + 1)
			blockValue := binary.BigEndian.Uint64(block[:8]) ^ t
			binary.BigEndian.PutUint64(block[:8], blockValue)

			// - R[i] = LSB(64, B)
			copy(intermediate[j*8:j*8+8], block[8:])
		}
	}

	// 3) Output results.
	// - Set C[0] = A
	// - For i = 1 to n
	// -   C[i] = R[i]
	return append(block[:8], intermediate...), nil
}
