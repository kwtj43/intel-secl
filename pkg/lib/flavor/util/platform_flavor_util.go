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
		tpm.Meta.TPMVersion = hostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		// split into list
		tpm.Meta.PCRBanks = strings.Split(hostInfo.HardwareFeatures.TPM.Meta.PCRBanks, constants.PCRBankSeparator)
		feature.TPM = tpm

		txt := fm.HardwareFeature{}
		// Set TXT Feature presence
		txt.Enabled = hostInfo.HardwareFeatures.TXT.Enabled
		feature.TXT = txt

		cbnt := fm.CBNT{}
		// set CBNT
		cbnt.Enabled = hostInfo.HardwareFeatures.CBNT.Enabled
		cbnt.Meta.Profile = hostInfo.HardwareFeatures.CBNT.Meta.Profile
		// KWT cbnt.Meta.MSR = hostInfo.HardwareFeatures.CBNT.Meta.MSR
		feature.CBNT = cbnt

		uefi := fm.UEFI{}
		// and UEFI state
		uefi.Enabled = hostInfo.HardwareFeatures.UEFI.Enabled
		uefi.Meta.SecureBootEnabled = hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled
		feature.UEFI = uefi

		bmc := fm.HardwareFeature{}
		// Set BMC Feature presence
		bmc.Enabled = hostInfo.HardwareFeatures.BMC.Enabled
		feature.BMC = bmc

		pfr := fm.HardwareFeature{}
		// Set PFR Feature presence
		pfr.Enabled = hostInfo.HardwareFeatures.PFR.Enabled
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
func (pfutil PlatformFlavorUtil) GetPcrDetails(pcrManifest hcTypes.PcrManifest, pcrList []int, includeEventLog bool) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx {
	log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Leaving")

	pcrsWithDigestAlgorithmForFlavor := make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx)

	for _, digestBank := range pcrManifest.GetPcrBanks() {
		pcrsForFlavor := make(map[hcTypes.PcrIndex]fm.PcrEx)
		var digestAlgorithm crypt.DigestAlgorithm
		switch digestBank {
		case hcTypes.SHA1:
			digestAlgorithm = crypt.SHA1()
		case hcTypes.SHA256:
			digestAlgorithm = crypt.SHA256()
		}

		// pull out the logs for the required PCRs from both banks
		for _, pcrIndex := range pcrList {
			pI := hcTypes.PcrIndex(pcrIndex)
			var pcrInfo *hcTypes.Pcr
			pcrInfo, _ = pcrManifest.GetPcrValue(digestBank, pI)

			if pcrInfo != nil {
				// build the PcrEx which will hold the PcrValue and EventLogs
				var currPcrEx fm.PcrEx

				// Populate Value
				currPcrEx.Value = pcrInfo.Value

				// Event logs if allowed
				if includeEventLog {
					manifestPcrEventLogs, err := pcrManifest.GetPcrEventLog(digestBank, pI)

					// check if returned logset from PCR is nil
					if manifestPcrEventLogs != nil && err == nil {
						// Convert EventLog to flavor format
						for _, manifestEventLog := range manifestPcrEventLogs {
							var currPcrEvent hcTypes.EventLog
							currPcrEvent = manifestEventLog
							currPcrEx.Event = append(currPcrEx.Event, currPcrEvent)
						}
					}
				}

				// commit to sha-bank
				pcrsForFlavor[hcTypes.PcrIndex(pcrIndex)] = currPcrEx
			}
		}

		// commit pcr sha-bank to the overall map
		pcrsWithDigestAlgorithmForFlavor[digestAlgorithm] = pcrsForFlavor
	}
	// return map for flavor to use
	return pcrsWithDigestAlgorithmForFlavor
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

// copyInstanceOfPcrDetails - returns a full-clone of the PCRManifest state from the HostManifest
func (pfutil PlatformFlavorUtil) copyInstanceOfPcrDetails(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx {
	log.Trace("flavor/util/platform_flavor_util:copyInstanceOfPcrDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:copyInstanceOfPcrDetails() Leaving")

	var pcrDetailsCopy = make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx)

	for digestAlgorithm, pcrBank := range pcrDetails {
		var newPcrIndexMap = make(map[hcTypes.PcrIndex]fm.PcrEx)
		for pI, pE := range pcrBank {
			newPcrIndexMap[pI] = pE
		}
		pcrDetailsCopy[digestAlgorithm] = newPcrIndexMap
	}
	return pcrDetailsCopy
}

// IncludeModulesToEventLog includes the event logs from HostManifest in the respective PCR event log
func (pfutil PlatformFlavorUtil) IncludeModulesToEventLog(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx, modulesToInclude map[string]int) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx {
	log.Trace("flavor/util/platform_flavor_util:IncludeModulesToEventLog() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:IncludeModulesToEventLog() Leaving")

	filteredPcrDetails := pfutil.copyInstanceOfPcrDetails(pcrDetails)
	// loop across digest banks
	for digestAlgo, pcrMap := range filteredPcrDetails {
		// loop across pcrindex for each digestbank
		for pI, pE := range pcrMap {
			// include only the events that are needed since it's much harder to remove events
			// from a slice
			var eventsToInclude []hcTypes.EventLog

			// Loop through each event and see if it contains a ComponentName key/value.
			// If it does, see if the ComponentName exists in the 'modulesToInclude' map,
			// and if not, do not add it to the result.
			for _, eIX := range pE.Event {
				if componentName, ok := eIX.Info["ComponentName"]; ok {
					if _, ok := modulesToInclude[componentName]; !ok {
						continue
					}
				}

				// Remove the dynamic modules for VMware
				if eventName, ok := eIX.Info["EventName"]; ok && strings.ToLower(eventName) ==
					strings.ToLower(constants.VMWareComponentName) {
					if packageName, ok := eIX.Info["PackageName"]; ok && len(packageName) == 0 {
						continue
					}
				}

				log.Debugf("Including module '%s' - '%s' for PCR '%s'", eIX.Label, eIX.Info["ComponentName"], pI.String())
				eventsToInclude = append(eventsToInclude, eIX)
			}

			// add ONLY included events to the list
			pE.Event = eventsToInclude
			filteredPcrDetails[digestAlgo][pI] = pE
		}
	}
	return filteredPcrDetails
}

// ExcludeModulesFromEventLog - excludes the event logs from HostManifest out of the respective PCR event log
func (pfutil PlatformFlavorUtil) ExcludeModulesFromEventLog(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx, modulesToExclude map[string]int) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]fm.PcrEx {
	log.Trace("flavor/util/platform_flavor_util:ExcludeModulesFromEventLog() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:ExcludeModulesFromEventLog() Leaving")

	filteredPcrDetails := pfutil.copyInstanceOfPcrDetails(pcrDetails)
	// loop across digest banks
	for digestAlgo, pcrMap := range filteredPcrDetails {
		// loop across pcrindex for each digestbank
		for pI, pE := range pcrMap {
			// include only the events that are needed since it's much harder to remove events
			// from a slice
			var eventsToInclude []hcTypes.EventLog

			// Loop through each event and see if it contains a ComponentName key/value.
			// If it does, see if the ComponentName exists in the 'modulesToExclude' map,
			// and if so, do not add it to the result.
			for _, eIX := range pE.Event {
				if componentName, ok := eIX.Info["ComponentName"]; ok {
					if _, ok := modulesToExclude[componentName]; ok {
						log.Debugf("Excluding module '%s' - '%s' for PCR '%s'", eIX.Label, eIX.Info["ComponentName"], pI.String())
						continue
					}
				}

				// Remove the dynamic modules for VMware
				if eventName, ok := eIX.Info["EventName"]; ok && strings.ToLower(eventName) ==
					strings.ToLower(constants.VMWareComponentName) {
					if packageName, ok := eIX.Info["PackageName"]; ok && len(packageName) == 0 {
						log.Debugf("Excluding module '%s' - '%s' for PCR '%s'", eIX.Label, eIX.Info["ComponentName"], pI.String())
						continue
					}
				}

				eventsToInclude = append(eventsToInclude, eIX)
			}

			// add ONLY included events to the list
			pE.Event = eventsToInclude
			filteredPcrDetails[digestAlgo][pI] = pE
		}
	}
	return filteredPcrDetails
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
