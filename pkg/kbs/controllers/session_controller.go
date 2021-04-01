/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keytransfer"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/session"
	commConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type SessionController struct {
	config           *config.Configuration
	trustedCaCertDir string
}

func NewSessionController(kc *config.Configuration, caCertDir string) *SessionController {
	return &SessionController{config: kc,
		trustedCaCertDir: caCertDir,
	}
}

// from challenge uuid remove '-' and prepare nonce
func getNonce(challengeUUID string) ([]byte, error) {
	decodedUUID, err := base64.StdEncoding.DecodeString(challengeUUID)
	if err != nil {
		return nil, errors.New("not a base64 encoded Challenge UUID")
	}
	nonce := make([]byte, constants.NonceLength)
	for i, j := 0, 0; i < len(decodedUUID); i++ {
		if decodedUUID[i] != '-' {
			nonce[j] = decodedUUID[i]
			j++
		}
	}
	return nonce, nil
}

// remove public key blob from quote received from skc client
// send only sgx ecdsa quote to quote verification service
func extractKeyFromQuote(quote string) (string, []byte, error) {
	decodedQuote, err := base64.StdEncoding.DecodeString(quote)
	if err != nil {
		return "", nil, errors.New("not a base64 encoded Quote")
	}
	// quote starts with 4 bytes for key exponent length
	// next four bytes account for modulus length
	pubKeyExponent := binary.LittleEndian.Uint32(decodedQuote[:])
	pubKeyModulus := binary.LittleEndian.Uint32(decodedQuote[4:])
	pubKeySize := int(pubKeyModulus + pubKeyExponent)
	// 12 bytes below account for key exponent/modulus length and quote size
	pubKeyStart := 12
	pubKeyEnd := pubKeyStart + pubKeySize

	publicKey := make([]byte, pubKeySize)
	copy(publicKey, decodedQuote[pubKeyStart:pubKeyEnd])

	newSize := len(decodedQuote) - pubKeySize - pubKeyStart
	quoteWithoutKey := make([]byte, newSize)
	quoteStart := pubKeyStart + pubKeySize
	quoteEnd := len(decodedQuote)
	copy(quoteWithoutKey, decodedQuote[quoteStart:quoteEnd])
	encodedQuote := base64.StdEncoding.EncodeToString(quoteWithoutKey)
	return encodedQuote, publicKey, nil
}

// public key and nonce are appended and base64 encoded as userData to QVS
func addKeyandNonce(key []byte, nonce []byte) string {
	return base64.StdEncoding.EncodeToString(append(key, nonce...))
}

func (sc *SessionController) Create(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/session_controller:Create() Entering")
	defer defaultLog.Trace("controllers/session_controller:Create() Leaving")

	if request.Header.Get("Content-Type") != commConstants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/session_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var sessionRequest kbs.SessionManagementAttributes

	// Decode the incoming json data to note struct
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&sessionRequest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/session_controller:Create() %s : Failed to decode request body as SessionManagementAttributes", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateSessionCreateRequest(sessionRequest)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() Invalid create request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid create request"}
	}

	swQuote, err := checkAndvalidateSwQuote(sessionRequest)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() invalid quote")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "quote parameters mismatch"}
	}

	keyInfo := keytransfer.GetKeyInfo()
	sessionObj := keyInfo.GetSessionObj(sessionRequest.Challenge)

	if reflect.DeepEqual(sessionObj, kbs.KeyTransferSession{}) {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() no session object found.")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "no session object found"}
	}
	var resAttr kbs.QuoteVerifyAttributes
	var responseAttributes *kbs.QuoteVerifyAttributes
	rsaKey, err := getRsaPubKey(sessionRequest.Quote)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "rsa key extraction failed"}
	}
	if swQuote {
		resAttr.Message = "Software(SW) Quote Verification Successful"
		resAttr.ChallengeKeyType = constants.CRYPTOALG_RSA
		resAttr.ChallengeRsaPublicKey = string(rsaKey)
		responseAttributes = &resAttr
	} else {
		nonce, err := getNonce(sessionRequest.Challenge)
		if err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in fetching the nonce"}
		}
		Quote, Key, err := extractKeyFromQuote(sessionRequest.Quote)
		if err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while extracting public key"}
		}
		UserData := addKeyandNonce(Key, nonce)
		// send ecdsa quote and user data(Enclave Public Key + nonce) to Quote Verification Service
		responseAttributes, err = session.VerifyQuote(Quote, UserData, sc.config, sc.trustedCaCertDir)
		if err != nil || responseAttributes == nil {
			secLog.WithError(err).Error("controllers/session_controller:Create() Remote attestation for new session failed")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Remote attestation for new session failed"}
		}
		responseAttributes.ChallengeKeyType = constants.CRYPTOALG_RSA
		responseAttributes.ChallengeRsaPublicKey = string(rsaKey)
	}
	keyInfo.SessionResponseMap[sessionRequest.Challenge] = *responseAttributes

	swkKey, err := session.SessionCreateSwk()
	if err != nil {
		secLog.Error("controllers/session_controller:Create() Error in getting SWK key")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in getting SWK key"}
	}

	sessionObj.SWK = swkKey
	keyInfo.SessionMap[sessionRequest.Challenge] = sessionObj

	var respAttr kbs.SessionResponseAttributes
	if responseAttributes.ChallengeKeyType == constants.CRYPTOALG_RSA {
		wrappedKey, err := session.SessionWrapSwkWithRSAKey(responseAttributes.ChallengeKeyType, rsaKey, sessionObj.SWK)
		if err != nil {
			secLog.Error("controllers/session_controller:Create() Unable to wrap the swk with rsa key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in wrapping SWK key with RSA key"}

		}
		respAttr.SessionData.SWK = wrappedKey
		if sessionRequest.ChallengeType == constants.SWAlgorithmType {
			respAttr.SessionData.AlgorithmType = constants.SWAlgorithmType
		} else {
			respAttr.SessionData.AlgorithmType = constants.SGXAlgorithmType
		}
		respAttr.Operation = constants.SessionOperation
		respAttr.Status = constants.SuccessStatus
	} else {
		secLog.Error("controllers/session_controller:Create() Currently only RSA key support is available")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Currently only RSA key support is available"}
	}

	sessionIDStr := fmt.Sprintf("%s:%s", sessionRequest.ChallengeType, sessionRequest.Challenge)
	responseWriter.Header().Add("Session-Id", sessionIDStr)

	secLog.WithField("Session-Id", sessionIDStr).Infof("controllers/session_controller:Create(): Successfully created session: %s", request.RemoteAddr)

	return respAttr, http.StatusCreated, nil
}

func validateSessionCreateRequest(sessionRequest kbs.SessionManagementAttributes) error {
	defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Entering")
	defer defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Leaving")

	if sessionRequest.ChallengeType == "" || sessionRequest.Challenge == "" || sessionRequest.Quote == "" {
		return errors.New("challenge_type/challenge/quote parameters are missing")
	}

	if sessionRequest.ChallengeType != constants.DefaultSWLabel && sessionRequest.ChallengeType != constants.DefaultSGXLabel {
		return errors.New("challenge_type parameter is not correct.")
	}

	if err := validation.ValidateBase64String(sessionRequest.Challenge); err != nil {
		return errors.New("Challenge is not a base64 string")
	}
	return nil
}

func checkAndvalidateSwQuote(sessionRequest kbs.SessionManagementAttributes) (bool, error) {
	defaultLog.Trace("controllers/session_controller:checkAndvalidateSwQuote() Entering")
	defer defaultLog.Trace("controllers/session_controller:checkAndvalidateSwQuote() Leaving")

	decodedQuote, err := base64.StdEncoding.DecodeString(sessionRequest.Quote)
	if err != nil {
		return false, errors.New("not a base64 encoded quote")
	}
	quoteSize := binary.LittleEndian.Uint32(decodedQuote[8:])

	var quoteType string
	if quoteSize == 0 {
		quoteType = "SW"
	} else {
		quoteType = "SGX"
	}
	if quoteType != sessionRequest.ChallengeType {
		return false, errors.New("quotetype in quote header does not match with accept-challenge")
	}

	keyInfo := keytransfer.GetKeyInfo()
	sessionObj := keyInfo.GetSessionObj(sessionRequest.Challenge)

	if sessionObj.Stmlabel != sessionRequest.ChallengeType {
		return false, errors.New("challenge type in request does not match with existing session")
	}

	if sessionObj.SessionId == sessionRequest.Challenge && len(sessionObj.SWK) != 0 {
		return false, errors.New("using existing challenge for establishing new session")
	}

	if quoteType == "SW" {
		return true, nil
	}
	return false, nil
}

// getRsaPubKey extracts the modulus/exponent values and public key blob
// from the quote and generates a public key object.
// pubkey exponent len : 4 bytes
// pubkey modulus len : 4 bytes
// quote blob  : 4 bytes
// exponent value
// modulus value
func getRsaPubKey(quoteStr string) ([]byte, error) {
	defaultLog.Trace("controllers/session_controller:getRsaPubKey() Entering")
	defer defaultLog.Trace("controllers/session_controller:getRsaPubKey() Leaving")

	quote, err := base64.StdEncoding.DecodeString(quoteStr)
	if err != nil {
		return nil, errors.New("not a base64 encoded quote")
	}

	pubKeyExponent := binary.LittleEndian.Uint32(quote[:])
	pubKeyModulus := binary.LittleEndian.Uint32(quote[4:])
	pubKeySize := int(pubKeyModulus + pubKeyExponent)

	// first 12 byted contain key exponent/modulus length and quote size
	// after that the public key blob starts
	pubKeyStart := 12
	pubKeyEnd := pubKeyStart + pubKeySize

	publicKey := make([]byte, pubKeySize)
	copy(publicKey, quote[pubKeyStart:pubKeyEnd])

	n := big.Int{}
	n.SetBytes(publicKey[pubKeyExponent:])
	eb := big.Int{}
	eb.SetBytes(publicKey[:pubKeyExponent])

	pubKey := rsa.PublicKey{N: &n, E: int(eb.Int64())}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "GetRsaPubKey: Marshal error")
	}

	rsaPem := pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}
	rsaBytes := pem.EncodeToMemory(&rsaPem)
	if rsaBytes == nil {
		return nil, errors.Wrap(err, "GetRsaPubKey: Pem Encode failed")
	}

	return rsaBytes, nil
}
