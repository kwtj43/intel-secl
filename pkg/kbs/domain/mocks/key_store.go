/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"reflect"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()

// MockKeyStore provides a mocked implementation of interface domain.KeyStore
type MockKeyStore struct {
	KeyStore map[uuid.UUID]*models.KeyAttributes
}

// Create inserts a Key into the store
func (store *MockKeyStore) Create(k *models.KeyAttributes) (*models.KeyAttributes, error) {
	store.KeyStore[k.ID] = k
	return k, nil
}

// Retrieve returns a single Key record from the store
func (store *MockKeyStore) Retrieve(id uuid.UUID) (*models.KeyAttributes, error) {
	if k, ok := store.KeyStore[id]; ok {
		return k, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes Key from the store
func (store *MockKeyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyStore[id]; ok {
		delete(store.KeyStore, id)
		return nil
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a filtered list of Keys per the provided KeyFilterCriteria
func (store *MockKeyStore) Search(criteria *models.KeyFilterCriteria) ([]models.KeyAttributes, error) {

	var keys []models.KeyAttributes
	// start with all records
	for _, k := range store.KeyStore {
		keys = append(keys, *k)
	}

	// Key filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyFilterCriteria{}) {
		return keys, nil
	}

	// Algorithm filter
	if criteria.Algorithm != "" {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.Algorithm == criteria.Algorithm {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// KeyLength filter
	if criteria.KeyLength != 0 {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.KeyLength == criteria.KeyLength {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// CurveType filter
	if criteria.CurveType != "" {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.CurveType == criteria.CurveType {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// TransferPolicyId filter
	if criteria.TransferPolicyId != uuid.Nil {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.TransferPolicyId == criteria.TransferPolicyId {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	return keys, nil
}

// NewFakeKeyStore loads dummy data into MockKeyStore
func NewFakeKeyStore() *MockKeyStore {
	store := &MockKeyStore{}
	store.KeyStore = make(map[uuid.UUID]*models.KeyAttributes)

	_, err := store.Create(&models.KeyAttributes{
		ID:               uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Algorithm:        "AES",
		KeyLength:        256,
		KeyData:          "",
		KmipKeyID:        "1",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "https://localhost:9443/kbs/v1/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&models.KeyAttributes{
		ID:               uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Algorithm:        "EC",
		CurveType:        "prime256v1",
		PublicKey:        "",
		PrivateKey:       "",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "https://localhost:9443/kbs/v1/keys/e57e5ea0-d465-461e-882d-1600090caa0d/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&models.KeyAttributes{
		ID:               uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
		Algorithm:        "RSA",
		KeyLength:        2048,
		PublicKey:        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2puWkz8QzhquzhOpgBnTvWHfhTi4KOUtIormEu+cIpCmKgaHOwYddToXG/bPYNQslRJQ+VSFF9BRMm2i+lFWQK0UdEUEIOfV9CurMclM4fkiGxRw28Rdhp5X2X6XkNjKXRf2YNlguyq4ocH8mL2h6Pcpff30ikzgHfV3TRAJFLq21Uc0WVC6JYP7naWOiDIZOix7c9RRaGV4wEIstc+g+UhdM08JD+cBrQeIHL0odu5/aLBMS1JoFKfG2AYxIDvT394MdqW7oNbHMszRGXzPz4lryGgOeLQhCfdWYOwF3jNR8M5I4mzPzfadXnGIGiEfpmk4ow9kvOyDMFNJelkENwIDAQAB",
		PrivateKey:       "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDam5aTPxDOGq7OE6mAGdO9Yd+FOLgo5S0iiuYS75wikKYqBoc7Bh11Ohcb9s9g1CyVElD5VIUX0FEybaL6UVZArRR0RQQg59X0K6sxyUzh+SIbFHDbxF2GnlfZfpeQ2MpdF/Zg2WC7KrihwfyYvaHo9yl9/fSKTOAd9XdNEAkUurbVRzRZULolg/udpY6IMhk6LHtz1FFoZXjAQiy1z6D5SF0zTwkP5wGtB4gcvSh27n9osExLUmgUp8bYBjEgO9Pf3gx2pbug1scyzNEZfM/PiWvIaA54tCEJ91Zg7AXeM1HwzkjibM/N9p1ecYgaIR+maTijD2S87IMwU0l6WQQ3AgMBAAECggEAVX009F5cVw1uQN7FkXgIKu6Ed9fHhQ6iiPiiotMbTxUcNiEZb0aj7H0MHn51eNtgl+dyzR51ceugZUUk0BlQzrgg4JtA0xF2xSbyquSa8V/5K3fh7r+rB4MSvdZYtWdiM+e0DQnVXzyEuZVgD+dQ0wcdLc1LfW400uJ0hil4M6dbUN+9Mr0Q0U2oyobeMGeDfq4nDn9OOq/bNZ2UsEacYlOVzAVyWRji8dKLLsDaLcyQycp0IUiJZCVGOLT1xl6WoAJqJDNrG8HSj2OHq3DbRUO7AeD7Zm75KfR6uUCiXmkUjbLxWZJICDF4pIK/uRBsWzzXX4cxNCMp3xcPMxRH6QKBgQD/8uMZsg/0wBljKGkF5jAohpYkPnL0JkfShk7Db+uYjjQvdMb0Nb+k5Hr4pAEQi5mWI3c9HCTzdVlKUYXqAF+rlr5NfTMv20slIIYrXOYveQMdxOZFCXQyofaaQGQ2sDrSixwfw5+5tg8pOeMMp0bchhB8fAfoDF36zQithCnxmwKBgQDapsm6cANQrLiJSxPfZE95Mehe0Ds10rDxiU2Td3YrtXwepTKlAOCm8TpkuiFcAXBvJSqyRazniQkAYFAB+DD4qeJN2K3Q1OiicufVkBLUGR/JxHVgzIfDkMUvf8JRGhlFWGBF3NRcrb1F6lQgQPpFkSWYx2HHCDvYqhT6IjL/lQKBgBOt6jY8kauA5bLRFZolg8hp6Ltqrc4F73nJZ97xCQ1Wyb5oXS/DvjOAedAKVCaghTOdEHr7Yf/yIuZq9D/0vWZlFcbBfKEOXG3DXW2SHATEai/sxsPCIVQPTfW4Q7xMuokbtxLeKLbPv8Sstb9wUSt9h2D67GS0Jrm08BjfU5ZHAoGAZqXsiIEznTko/RNpBfQCt2Ptsi1RzsfV197cs4Fe0dBGr+BgMUSDMvyGrGkRZi8qyJMLQ1wgeyZDOpD8nqAU5XhjzKYPm72IZVNKcWFM5ZPR75gyfromdnJNkCoLYKW+/WYq9EFi1QufkuYajnXSyLwGiX348kZ0Shg29uL9TC0CgYAG/blyqc4yqy7+P+aserSia7GX1pXFgrXUTPUUHwYp4ZmzJ905vOXKUqkVRld/iMs4tNWQTP0FOUjUn1zGQ/wjjqz9bMk6ouzUdO2Qri87KeJ0I3ifCCVtztA1LkntnHZKk5UZHwsS3blWHhduBDb8tNeDTRdeADaAjawB9S+57w==",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "https://localhost:9443/kbs/v1/keys/87d59b82-33b7-47e7-8fcb-6f7f12c82719/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating key attributes")
	}

	return store
}
