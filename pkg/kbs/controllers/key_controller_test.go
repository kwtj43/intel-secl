/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	kbsRoutes "github.com/intel-secl/intel-secl/v3/pkg/kbs/router"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	samlCertsDir          = "./resources/saml/"
	trustedCaCertsDir     = "./resources/trustedca/"
	tpmIdentityCertsDir   = "./resources/tpm-identity/"
	validSamlReportPath   = "./resources/saml_report.xml"
	invalidSamlReportPath = "./resources/invalid_saml_report.xml"
	endpointUrl           = "https://localhost:9443/kbs/v1"
)

var _ = Describe("KeyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var keyStore *mocks.MockKeyStore
	var policyStore *mocks.MockKeyTransferPolicyStore
	var remoteManager *keymanager.RemoteManager
	var keyController *controllers.KeyController
	var keyControllerConfig domain.KeyControllerConfig

	keyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &keyPair.PublicKey
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	validEnvelopeKey := pem.EncodeToMemory(publicKeyInPem)

	keyPair15360, _ := rsa.GenerateKey(rand.Reader, 15360)
	publicKey15360 := &keyPair15360.PublicKey
	pubKeyBytes15360, _ := x509.MarshalPKIXPublicKey(publicKey15360)
	var publicKeyInPem15360 = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes15360,
	}
	validEnvelopeKey15360 := pem.EncodeToMemory(publicKeyInPem15360)

	invalidEnvelopeKey := strings.Replace(strings.Replace(string(validEnvelopeKey), "-----BEGIN PUBLIC KEY-----\n", "", 1), "-----END PUBLIC KEY-----", "", 1)
	validSamlReport, _ := ioutil.ReadFile(validSamlReportPath)
	invalidSamlReport, _ := ioutil.ReadFile(invalidSamlReportPath)

	BeforeEach(func() {
		router = mux.NewRouter()
		keyStore = mocks.NewFakeKeyStore()
		policyStore = mocks.NewFakeKeyTransferPolicyStore()
		newId, err := uuid.NewRandom()
		Expect(err).NotTo(HaveOccurred())
		keyControllerConfig = domain.KeyControllerConfig{
			SamlCertsDir:            samlCertsDir,
			TrustedCaCertsDir:       trustedCaCertsDir,
			TpmIdentityCertsDir:     tpmIdentityCertsDir,
			DefaultTransferPolicyId: newId,
		}

		keyManager := &keymanager.DirectoryManager{}
		remoteManager = keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
		keyController = controllers.NewKeyController(remoteManager, policyStore, keyControllerConfig)
	})

	// Specs for HTTP Post to "/keys"
	Describe("Create a new Key", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES",
									"key_length": 256
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Create request that contains non-existent key-transfer-policy", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES",
									"key_length": 256
								},
								"transfer_policy_id": ""
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without algorithm", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"key_length": 256
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid algorithm", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "XYZ",
									"key_length": 256
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without key length", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES"
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid key length", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES",
									"key_length": 123
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without curve type", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "EC"
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid curve type", func() {
			It("Should fail to create new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "EC",
									"curve_type": "xyz123"
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Register a new Key", func() {
		Context("Provide a valid Register request", func() {
			It("Should register a new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES",
									"key_length": 256,
									"key_string": "oyGHF9EkKCp44KKADUhR/cNeSB8NJE7kazhNX/x5eio="
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyRegister},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Register request that contains malformed key", func() {
			It("Should fail to register new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods("POST")
				keyJson := `{
								"key_information": {
									"algorithm": "AES",
									"key_length": 256,
									"key_string": "k@y"
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/keys",
					strings.NewReader(keyJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Post to "/keys/{id}/transfer"
	Describe("Transfer using public key", func() {
		Context("Provide a valid public key", func() {
			It("Should transfer an existing symmetric Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods("POST")
				envelopeKey := string(validEnvelopeKey)

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a valid public key", func() {
			It("Should transfer an existing Private Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods("POST")
				envelopeKey := string(validEnvelopeKey15360)

				req, err := http.NewRequest(
					"POST",
					"/keys/87d59b82-33b7-47e7-8fcb-6f7f12c82719/transfer",
					strings.NewReader(envelopeKey),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a public key without PUBLIC KEY headers", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods("POST")
				envelopeKey := invalidEnvelopeKey

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a public key without DER data", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods("POST")
				envelopeKey := `-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existent Key id", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods("POST")
				envelopeKey := string(validEnvelopeKey)

				req, err := http.NewRequest(
					"POST",
					"/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer",
					strings.NewReader(envelopeKey),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	Describe("Transfer using saml report", func() {
		Context("Provide a valid saml report", func() {
			It("Should transfer an existing Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.TransferWithSaml))).Methods("POST")
				samlReport := string(validSamlReport)

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a saml report with overall trust false", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.TransferWithSaml))).Methods("POST")
				samlReport := strings.ReplaceAll(string(validSamlReport), "true", "false")

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide a saml report with unknown signer", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.TransferWithSaml))).Methods("POST")
				samlReport := string(invalidSamlReport)

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide an invalid saml report", func() {
			It("Should fail to transfer Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.TransferWithSaml))).Methods("POST")
				samlReport := `saml`

				req, err := http.NewRequest(
					"POST",
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/keys/{id}"
	Describe("Retrieve an existing Key", func() {
		Context("Retrieve Key by ID", func() {
			It("Should retrieve a Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Key by non-existent ID", func() {
			It("Should fail to retrieve Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/keys/{id}"
	Describe("Delete an existing Key", func() {
		Context("Delete Key by ID", func() {
			It("Should delete a Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/keys/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Key by non-existent ID", func() {
			It("Should fail to delete Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/keys/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/keys"
	Describe("Search for all the Keys", func() {
		Context("Get all the Keys", func() {
			It("Should get list of all the Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 3 keys
				Expect(len(keyResponses)).To(Equal(3))
			})
		})
		Context("Get all the Keys with unknown query parameter", func() {
			It("Should fail to get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?badparam=value", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid algorithm param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?algorithm=AES", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 1 key
				Expect(len(keyResponses)).To(Equal(1))
			})
		})
		Context("Get all the Keys with invalid algorithm param", func() {
			It("Should fail to get Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?algorithm=AE$", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid keyLength param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?keyLength=256", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 1 key
				Expect(len(keyResponses)).To(Equal(1))
			})
		})
		Context("Get all the Keys with invalid keyLength param", func() {
			It("Should fail to get Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?keyLength=abc", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid curveType param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?curveType=prime256v1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 1 key
				Expect(len(keyResponses)).To(Equal(1))
			})
		})
		Context("Get all the Keys with invalid curveType param", func() {
			It("Should fail to get Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?curveType=primev!", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid transferPolicyId param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?transferPolicyId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 3 keys
				Expect(len(keyResponses)).To(Equal(3))
			})
		})
		Context("Get all the Keys with invalid transferPolicyId param", func() {
			It("Should fail to get Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/keys?transferPolicyId=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
