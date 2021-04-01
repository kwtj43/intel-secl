/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"encoding/xml"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	fm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// PlatformFlavorUtil is used to group a collection of utility functions dealing with PlatformFlavor
type PlatformFlavorUtil struct {
}

// GetMetaSectionDetails returns the Meta instance from the HostManifest
func (pfutil PlatformFlavorUtil) GetMetaSectionDetails(hostDetails *taModel.HostInfo, tagCertificate *fm.X509AttributeCertificate,
	xmlMeasurement string, flavorPartName common.FlavorPart, vendor hcConstants.Vendor) (*fm.Meta, error) {
	log.Trace("flavor/util/platform_flavor_util:GetMetaSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetMetaSectionDetails() Leaving")

	var meta fm.Meta
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:GetMetaSectionDetails() failed to create new UUID")
	}
	// Set UUID
	meta.ID = newUuid
	meta.Vendor = vendor

	var biosName string
	var biosVersion string
	var osName string
	var osVersion string
	var vmmName string
	var vmmVersion string

	// Set Description
	var description = make(map[string]interface{})

	if hostDetails != nil {
		biosName = strings.TrimSpace(hostDetails.BiosName)
		biosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		description[fm.TbootInstalled] = &hostDetails.TbootInstalled
		vmmName = strings.TrimSpace(hostDetails.VMMName)
		vmmVersion = strings.TrimSpace(hostDetails.VMMVersion)
		osName = strings.TrimSpace(hostDetails.OSName)
		osVersion = strings.TrimSpace(hostDetails.OSVersion)
		description[fm.TpmVersion] = strings.TrimSpace(hostDetails.HardwareFeatures.TPM.Meta.TPMVersion)
	}

	switch flavorPartName {
	case common.FlavorPartPlatform:
		var features = pfutil.getSupportedHardwareFeatures(hostDetails)
		description[fm.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), biosName,
			biosVersion, strings.Join(features, "_"), pfutil.getCurrentTimeStamp())
		description[fm.BiosName] = biosName
		description[fm.BiosVersion] = biosVersion
		description[fm.FlavorPart] = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description[fm.Source] = strings.TrimSpace(hostDetails.HostName)
		}
	case common.FlavorPartOs:
		description[fm.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), osName, osVersion,
			vmmName, vmmVersion, pfutil.getCurrentTimeStamp())
		description[fm.OsName] = osName
		description[fm.OsVersion] = osVersion
		description[fm.FlavorPart] = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description[fm.Source] = strings.TrimSpace(hostDetails.HostName)
		}
		if vmmName != "" {
			description[fm.VmmName] = strings.TrimSpace(vmmName)
		}
		if vmmVersion != "" {
			description[fm.VmmVersion] = strings.TrimSpace(vmmVersion)
		}

	case common.FlavorPartSoftware:
		var measurements taModel.Measurement
		err := xml.Unmarshal([]byte(xmlMeasurement), &measurements)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse XML measurements in Software Flavor: %s", err.Error())
		}
		description[fm.Label] = measurements.Label
		description[fm.FlavorPart] = flavorPartName.String()
		// set DigestAlgo to SHA384
		switch strings.ToUpper(measurements.DigestAlg) {
		case crypt.SHA384().Name:
			description[fm.DigestAlgorithm] = crypt.SHA384().Name
		default:
			return nil, errors.Errorf("invalid Digest Algorithm in measurement XML")
		}
		meta.ID, err = uuid.Parse(measurements.Uuid)
		if err != nil {
			// if Software UUID is empty, we generate a new UUID and use it
			newUuid, err := uuid.NewRandom()
			if err != nil {
				return nil, errors.Wrap(err, "failed to create new UUID")
			}
			meta.ID = newUuid
		}
		meta.Schema = pfutil.getSchema()

	case common.FlavorPartAssetTag:
		description[fm.FlavorPart] = flavorPartName.String()
		if hostDetails != nil {
			hwuuid, err := uuid.Parse(hostDetails.HardwareUUID)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			}
			description[fm.HardwareUUID] = hwuuid.String()

			if hostDetails.HostName != "" {
				description[fm.Source] = strings.TrimSpace(hostDetails.HostName)
			}
		} else if tagCertificate != nil {
			hwuuid, err := uuid.Parse(tagCertificate.Subject)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			} else {
				description[fm.HardwareUUID] = hwuuid.String()
			}
		}
		description[fm.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), description[fm.HardwareUUID].(string), pfutil.getCurrentTimeStamp())

	case common.FlavorPartHostUnique:
		if hostDetails != nil {
			if hostDetails.HostName != "" {
				description[fm.Source] = strings.TrimSpace(hostDetails.HostName)
			}
			hwuuid, err := uuid.Parse(hostDetails.HardwareUUID)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			}
			description[fm.HardwareUUID] = hwuuid.String()
		}
		description[fm.BiosName] = biosName
		description[fm.BiosVersion] = biosVersion
		description[fm.OsName] = osName
		description[fm.OsVersion] = osVersion
		description[fm.FlavorPart] = flavorPartName.String()
		description[fm.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), description[fm.HardwareUUID].(string), pfutil.getCurrentTimeStamp())
	default:
		return nil, errors.Errorf("Invalid FlavorPart %s", flavorPartName.String())
	}
	meta.Description = description

	return &meta, nil
}

// GetBiosSectionDetails populate the BIOS field details in Flavor
func (pfutil PlatformFlavorUtil) GetBiosSectionDetails(hostDetails *taModel.HostInfo) *fm.Bios {
	log.Trace("flavor/util/platform_flavor_util:GetBiosSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetBiosSectionDetails() Leaving")

	var bios fm.Bios
	if hostDetails != nil {
		bios.BiosName = strings.TrimSpace(hostDetails.BiosName)
		bios.BiosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		return &bios
	}
	return nil
}

// getSchema sets the schema for the Meta struct in the flavor
func (pfutil PlatformFlavorUtil) getSchema() *fm.Schema {
	log.Trace("flavor/util/platform_flavor_util:getSchema() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getSchema() Leaving")

	var schema fm.Schema
	schema.Uri = constants.IslMeasurementSchema
	return &schema
}

// getHardwareSectionDetails extracts the host Hardware details from the manifest
func (pfutil PlatformFlavorUtil) GetHardwareSectionDetails(hostInfo *taModel.HostInfo) *fm.Hardware {
	log.Trace("flavor/util/platform_flavor_util:GetHardwareSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetHardwareSectionDetails() Leaving")

	var hardware fm.Hardware
	var feature fm.Feature

	if hostInfo != nil {
		// Extract Processor Info
		hardware.ProcessorInfo = strings.TrimSpace(hostInfo.ProcessorInfo)
		hardware.ProcessorFlags = strings.TrimSpace(hostInfo.ProcessorFlags)

		// Set TPM Feature presence
		tpm := fm.TPM{}
		tpm.Enabled = hostInfo.HardwareFeatures.TPM.Enabled
		tpm.Supported = hostInfo.HardwareFeatures.TPM.Supported

		tpm.Meta.TPMVersion = hostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		// split into list
		tpm.Meta.PCRBanks = strings.Split(hostInfo.HardwareFeatures.TPM.Meta.PCRBanks, constants.PCRBankSeparator)
		feature.TPM = tpm

		txt := fm.HardwareFeature{}
		// Set TXT Feature presence
		txt.Enabled = hostInfo.HardwareFeatures.TXT.Enabled
		txt.Supported = hostInfo.HardwareFeatures.TXT.Supported
		feature.TXT = txt

		cbnt := fm.CBNT{}
		// set CBNT
		cbnt.Enabled = hostInfo.HardwareFeatures.CBNT.Enabled
		cbnt.Supported = hostInfo.HardwareFeatures.CBNT.Supported
		cbnt.Meta.Profile = hostInfo.HardwareFeatures.CBNT.Meta.Profile
		cbnt.Meta.MSR = hostInfo.HardwareFeatures.CBNT.Meta.MSR
		feature.CBNT = cbnt

		uefi := fm.UEFI{}
		// and UEFI state
		uefi.Enabled = hostInfo.HardwareFeatures.UEFI.Enabled
		uefi.Supported = hostInfo.HardwareFeatures.UEFI.Supported
		uefi.Meta.SecureBootEnabled = hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled
		feature.UEFI = uefi

		bmc := fm.HardwareFeature{}
		// Set BMC Feature presence
		bmc.Enabled = hostInfo.HardwareFeatures.BMC.Enabled
		bmc.Supported = hostInfo.HardwareFeatures.BMC.Supported
		feature.BMC = bmc

		pfr := fm.HardwareFeature{}
		// Set PFR Feature presence
		pfr.Enabled = hostInfo.HardwareFeatures.PFR.Enabled
		pfr.Supported = hostInfo.HardwareFeatures.PFR.Supported
		feature.PFR = pfr

		hardware.Feature = &feature
	}
	return &hardware
}

// PcrExists checks if required list of PCRs are populated in the PCRManifest
func (pfutil PlatformFlavorUtil) PcrExists(pcrManifest hcTypes.PcrManifest, pcrList []int) bool {
	log.Trace("flavor/util/platform_flavor_util:PcrExists() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:PcrExists() Leaving")

	var pcrExists bool

	// check for empty pcrList
	if len(pcrList) == 0 {
		return pcrExists
	}

	for _, digestBank := range pcrManifest.GetPcrBanks() {
		var pcrExistsForDigestAlg bool

		for _, pcrIndex := range pcrList {
			// get PcrIndex
			pI := hcTypes.PcrIndex(pcrIndex)
			pcr, err := pcrManifest.GetPcrValue(digestBank, pI)

			if pcr != nil && err == nil {
				pcrExistsForDigestAlg = true
			}

			// This check ensures that even if PCRs exist for one supported algorithm, we
			// return back true.
			if pcrExistsForDigestAlg && !pcrExists {
				pcrExists = true
			}
		}
	}
	return pcrExists
}

// GetPcrDetails extracts Pcr values and Event Logs from the HostManifest/PcrManifest and  returns
// in a format suitable for inserting into the flavor
func (pfutil PlatformFlavorUtil) GetPcrDetails(pcrManifest hcTypes.PcrManifest, pcrList map[hvs.PCR]hvs.PcrListRules) []hcTypes.FlavorPcrs {
	log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Leaving")

	var pcrCollection []hcTypes.FlavorPcrs

	// pull out the logs for the required PCRs from both banks
	for pcr, rules := range pcrList {
		pI := hcTypes.PcrIndex(pcr.Index)
		var pcrInfo *hcTypes.HostManifestPcrs
		pcrInfo, _ = pcrManifest.GetPcrValue(hcTypes.SHAAlgorithm(pcr.Bank), pI)

		if pcrInfo != nil {
			var currPcrEx hcTypes.FlavorPcrs
			currPcrEx.Pcr.Index = pcr.Index
			currPcrEx.Pcr.Bank = pcr.Bank
			currPcrEx.Measurement = pcrInfo.Value
			if rules.PcrMatches {
				currPcrEx.PCRMatches = true
			}

			// Populate Event log value
			var eventLogEqualEvents []hcTypes.EventLog
			manifestPcrEventLogs, err := pcrManifest.GetEventLogCriteria(hcTypes.SHAAlgorithm(pcr.Bank), pI)

			// check if returned logset from PCR is nil
			if manifestPcrEventLogs != nil && err == nil {

				// Convert EventLog to flavor format
				for _, manifestEventLog := range manifestPcrEventLogs {
					if len(manifestEventLog.Tags) == 0 {
						if rules.PcrEquals.IsPcrEquals {
							eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
						}
					}
					presentInExcludeTag := false
					for _, tag := range manifestEventLog.Tags {
						if _, ok := rules.PcrIncludes[tag]; ok {
							currPcrEx.EventlogIncludes = append(currPcrEx.EventlogIncludes, manifestEventLog)
							break
						} else if rules.PcrEquals.IsPcrEquals {
							if _, ok := rules.PcrEquals.ExcludingTags[tag]; ok {
								presentInExcludeTag = true
								break
							}
						}
					}
					if !presentInExcludeTag {
						eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
					}
				}
				if rules.PcrEquals.IsPcrEquals {
					var EventLogExcludes []string
					for excludeTag, _ := range rules.PcrEquals.ExcludingTags {
						EventLogExcludes = append(EventLogExcludes, excludeTag)
					}
					currPcrEx.EventlogEqual = &hcTypes.EventLogEqual{
						Events:      eventLogEqualEvents,
						ExcludeTags: EventLogExcludes,
					}
				}
			}
			pcrCollection = append(pcrCollection, currPcrEx)
		}
	}
	// return map for flavor to use
	return pcrCollection
}

// GetExternalConfigurationDetails extracts the External field for the flavor from the HostManifest
func (pfutil PlatformFlavorUtil) GetExternalConfigurationDetails(tagCertificate *fm.X509AttributeCertificate) (*fm.External, error) {
	log.Trace("flavor/util/platform_flavor_util:GetExternalConfigurationDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetExternalConfigurationDetails() Leaving")

	var externalconfiguration fm.External
	var assetTag fm.AssetTag

	if tagCertificate == nil {
		return nil, errors.Errorf("Specified tagcertificate is not valid")
	}
	assetTag.TagCertificate = *tagCertificate
	externalconfiguration.AssetTag = assetTag
	return &externalconfiguration, nil
}

// getSupportedHardwareFeatures returns a list of hardware features supported by the host from its HostInfo
func (pfutil PlatformFlavorUtil) getSupportedHardwareFeatures(hostDetails *taModel.HostInfo) []string {
	log.Trace("flavor/util/platform_flavor_util:getSupportedHardwareFeatures() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getSupportedHardwareFeatures() Leaving")

	var features []string
	if hostDetails.HardwareFeatures.CBNT.Enabled {
		features = append(features, constants.Cbnt)
		features = append(features, hostDetails.HardwareFeatures.CBNT.Meta.Profile)
	}

	if hostDetails.HardwareFeatures.TPM.Enabled {
		features = append(features, constants.Tpm)
	}

	if hostDetails.HardwareFeatures.TXT.Enabled {
		features = append(features, constants.Txt)
	}

	if hostDetails.HardwareFeatures.UEFI.Enabled {
		features = append(features, constants.Uefi)
	}
	if hostDetails.HardwareFeatures.UEFI.Meta.SecureBootEnabled {
		features = append(features, constants.SecureBootEnabled)
	}

	return features
}

// getLabelFromDetails generates a flavor label string by combining the details
//from separate fields into a single string separated by underscore
func (pfutil PlatformFlavorUtil) getLabelFromDetails(names ...string) string {
	log.Trace("flavor/util/platform_flavor_util:getLabelFromDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getLabelFromDetails() Leaving")

	var labels []string
	for _, s := range names {
		labels = append(labels, strings.Join(strings.Fields(s), ""))
	}
	return strings.Join(labels, "_")
}

// getCurrentTimeStamp generates the current time in the required format
func (pfutil PlatformFlavorUtil) getCurrentTimeStamp() string {
	log.Trace("flavor/util/platform_flavor_util:getCurrentTimeStamp() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getCurrentTimeStamp() Leaving")

	// Use magical reference date to specify the format
	return time.Now().Format(constants.FlavorWoTimestampFormat)
}

// getSignedFlavorList performs a bulk signing of a list of flavor strings and returns a list of SignedFlavors
func (pfutil PlatformFlavorUtil) GetSignedFlavorList(flavors []fm.Flavor, flavorSigningPrivateKey *rsa.PrivateKey) ([]hvs.SignedFlavor, error) {
	log.Trace("flavor/util/platform_flavor_util:GetSignedFlavorList() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetSignedFlavorList() Leaving")

	var signedFlavors []hvs.SignedFlavor

	if flavors != nil {
		// loop through and sign each flavor
		for _, unsignedFlavor := range flavors {
			var sf *hvs.SignedFlavor
			sf, err := pfutil.GetSignedFlavor(&unsignedFlavor, flavorSigningPrivateKey)
			if err != nil {
				return nil, errors.Errorf("Error signing flavor collection: %s", err.Error())
			}
			signedFlavors = append(signedFlavors, *sf)
		}
	} else {
		return nil, errors.Errorf("empty flavors list provided")
	}

	return signedFlavors, nil
}

// GetSignedFlavor is used to sign the flavor
func (pfutil PlatformFlavorUtil) GetSignedFlavor(unsignedFlavor *hvs.Flavor, privateKey *rsa.PrivateKey) (*hvs.SignedFlavor, error) {
	log.Trace("flavor/util/platform_flavor_util:GetSignedFlavor() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetSignedFlavor() Leaving")

	if unsignedFlavor == nil {
		return nil, errors.New("GetSignedFlavor: Flavor content missing")
	}

	signedFlavor, err := fm.NewSignedFlavor(unsignedFlavor, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "GetSignedFlavor: Error while marshalling signed flavor")
	}

	return signedFlavor, nil
}

// GetPcrRulesMap Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware.
func (pfutil PlatformFlavorUtil) GetPcrRulesMap(flavorPart cf.FlavorPart, flavorTemplates []hvs.FlavorTemplate) (map[hvs.PCR]hvs.PcrListRules, error) {
	log.Trace("flavor/util/platform_flavor_util:getPcrRulesMap() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getPcrRulesMap() Leaving")

	pcrRulesForFlavorPart := make(map[hvs.PCR]hvs.PcrListRules)
	var err error
	for _, flavorTemplate := range flavorTemplates {
		switch flavorPart {
		case cf.FlavorPartPlatform:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.Platform, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for platform flavor")
			}
			break
		case cf.FlavorPartOs:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.OS, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for os flavor")
			}
			break
		case cf.FlavorPartHostUnique:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.HostUnique, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for host unique flavor")
			}
			break
		}
	}

	return pcrRulesForFlavorPart, nil
}

func getPcrRulesForFlavorPart(flavorPart *hvs.FlavorPart, pcrList map[hvs.PCR]hvs.PcrListRules) (map[hvs.PCR]hvs.PcrListRules, error) {
	log.Trace("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Leaving")

	if flavorPart == nil {
		return pcrList, nil
	}

	if pcrList == nil {
		pcrList = make(map[hvs.PCR]hvs.PcrListRules)
	}

	for _, pcrRule := range flavorPart.PcrRules {
		var rulesList hvs.PcrListRules

		if rules, ok := pcrList[pcrRule.Pcr]; ok {
			rulesList = rules
		}
		if pcrRule.PcrMatches != nil && *pcrRule.PcrMatches {
			rulesList.PcrMatches = true
		}
		if rulesList.PcrIncludes != nil && pcrRule.EventlogEquals != nil {
			return nil, errors.New("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Error getting pcrList : Both event log equals and includes rule present for single pcr index/bank")
		}
		if pcrRule.EventlogEquals != nil {
			rulesList.PcrEquals.IsPcrEquals = true
			if pcrRule.EventlogEquals.ExcludingTags != nil {
				rulesList.PcrEquals.ExcludingTags = make(map[string]bool)
				for _, tags := range pcrRule.EventlogEquals.ExcludingTags {
					if _, ok := rulesList.PcrEquals.ExcludingTags[tags]; !ok {
						rulesList.PcrEquals.ExcludingTags[tags] = false
					}
				}
			}
		}

		if rulesList.PcrEquals.IsPcrEquals == true && pcrRule.EventlogIncludes != nil {
			return nil, errors.New("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Error getting pcrList : Both event log equals and includes rule present for single pcr index/bank")
		}

		if pcrRule.EventlogIncludes != nil {
			rulesList.PcrIncludes = make(map[string]bool)
			for _, tags := range pcrRule.EventlogIncludes {
				if _, ok := rulesList.PcrIncludes[tags]; !ok {
					rulesList.PcrIncludes[tags] = true
				}
			}
		}
		pcrList[pcrRule.Pcr] = rulesList
	}

	return pcrList, nil
}
