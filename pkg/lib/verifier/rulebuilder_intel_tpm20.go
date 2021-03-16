/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "intel" vendor and TPM 2.0.
//

import (
	"reflect"

	hvsconstants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavormodel "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

type ruleBuilderIntelTpm20 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rules.Rule
}

func newRuleBuilderIntelTpm20(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (ruleBuilder, error) {
	builder := ruleBuilderIntelTpm20{
		verifierCertificates: verifierCertificates,
		hostManifest:         hostManifest,
		signedFlavor:         signedFlavor,
	}

	return &builder, nil
}

func (builder *ruleBuilderIntelTpm20) GetName() string {
	return hvsconstants.IntelBuilder
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrMatchesConstant depend on HW features present in flavor
// PcrEventLogEqualsExcluding rule for PCR 17, 18
// PcrEventLogIntegrity rule for PCR 17,18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetPlatformRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartPlatform)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting AikCertificateTrusted rule")
	}

	results = append(results, aikCertificateTrusted)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// AssetTagMatches
// FlavorTrusted
func (builder *ruleBuilderIntelTpm20) GetAssetTagRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// TagCertificateTrusted
	//
	tagCertificateTrusted, err := getTagCertificateTrustedRule(builder.verifierCertificates.AssetTagCACertificates, &builder.signedFlavor.Flavor)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting TagCertificateTrusted rule")
	}

	results = append(results, tagCertificateTrusted)

	//
	// AssetTagMatches
	//
	assetTagMatches, err := getAssetTagMatchesRule(&builder.signedFlavor.Flavor)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting AssetTagMatches rule")
	}

	results = append(results, assetTagMatches)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrEventLogIntegrity rule for PCR 17 (if tboot is installed)
// PcrEventLogIncludes rule for PCR 17
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetOsRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartOs)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting AikCertificateTrusted rule")
	}

	results = append(results, aikCertificateTrusted)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrEventLogIncludes rule for PCR 17, 18
// PcrEventLogIntegrity rule for PCR 17, 18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetHostUniqueRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartHostUnique)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting AikCertificateTrusted rule")
	}

	results = append(results, aikCertificateTrusted)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// XmlMeasurementsDigestEquals
// PcrEventLogIntegrity rule for PCR 15
// XmlMeasurementLogIntegrity
// XmlMeasurementLogEquals
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetSoftwareRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'XmlEventLogDigestEquals' rule...
	//
	meta := builder.signedFlavor.Flavor.Meta
	if reflect.DeepEqual(meta, flavormodel.Meta{}) {
		return nil, errors.New("'Meta' was not present in the flavor")
	}

	xmlMeasurementLogDigestEqualsRule, err := rules.NewXmlMeasurementLogDigestEquals(meta.Description[flavormodel.DigestAlgorithm].(string), meta.ID)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting xmlMeasurementLogDigestEquals rule")
	}

	results = append(results, xmlMeasurementLogDigestEqualsRule)

	//
	// Add 'XmlMeasurementLogIntegrity' rule...
	//
	if builder.signedFlavor.Flavor.Software == nil {
		return nil, errors.New("'Software' was not present in the flavor")
	}

	xmlMeasurementLogIntegrityRule, err := rules.NewXmlMeasurementLogIntegrity(meta.ID, meta.Description[flavormodel.Label].(string), builder.signedFlavor.Flavor.Software.CumulativeHash)
	results = append(results, xmlMeasurementLogIntegrityRule)

	//
	// Add 'XmlMeasurementLogEquals' rule...
	//
	var measurements []ta.FlavorMeasurement
	for _, measurement := range builder.signedFlavor.Flavor.Software.Measurements {
		measurements = append(measurements, measurement)
	}

	xmlMeasurementLogEqualsRule, err := rules.NewXmlMeasurementLogEquals(&builder.signedFlavor.Flavor)
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting NewXmlMeasurementLogEquals rule")
	}

	results = append(results, xmlMeasurementLogEqualsRule)

	return results, nil
}
