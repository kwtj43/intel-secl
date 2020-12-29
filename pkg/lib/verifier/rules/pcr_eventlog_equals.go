/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"
	"reflect"

	"github.com/google/uuid"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

var (
	// This is a map of component names to remove the host manifest's list of events.  The
	// map value (int) is not relevant, just use the map key for efficient lookups.
	defaultExcludeComponents = map[string]int{
		"commandLine.":              0,
		"LCP_CONTROL_HASH":          0,
		"initrd":                    0,
		"vmlinuz":                   0,
		"componentName.imgdb.tgz":   0,
		"componentName.onetime.tgz": 0,
	}

	// map of 'labels' to exclude during the evaluation of the host manifest
	defaultExcludeLabels = map[string]int{
		"0x4fe": 0,
	}
)

// This rule implements both PcrEventLogEquals and PcrEventLogEqualsExcluding.  Only
// the 'new' functions are different, populating the rule name and 'excludes'.
func NewPcrEventLogEquals(expectedPcrEventLogEntry *types.EventLogEntry, flavorID uuid.UUID, marker common.FlavorPart) (Rule, error) {

	// create the rule without the defaultExcludeComponents/labels so that all
	// events are evaluated (i.e. no 'excludes').
	rule := pcrEventLogEquals{
		expectedEventLogEntry: expectedPcrEventLogEntry,
		ruleName:              constants.RulePcrEventLogEquals,
		flavorID:              &flavorID,
		marker:                marker,
	}

	return &rule, nil
}

//This rule implements both PcrEventLogEquals and PcrEventLogEqualsExcluding.  Only
// the 'new' functions are different, populating the rule name and 'excludes'.
func NewPcrEventLogEqualsExcluding(expectedEventLogEntry *types.EventLogEntry, expectedPcr *types.Pcr, excludedEvents []string, flavorID uuid.UUID, marker common.FlavorPart) (Rule, error) {

	var rule pcrEventLogEquals

	if !reflect.DeepEqual(expectedEventLogEntry.PcrEventLogs, []types.EventLogCriteria{}) {
		rule = pcrEventLogEquals{
			expectedEventLogEntry: expectedEventLogEntry,
			excludeTags:           excludedEvents,
			marker:                marker,
			ruleName:              constants.RulePcrEventLogEqualsExcluding,
		}
	} else {
		// create the rule providing the defaultExcludeComponents and labels so
		// they are not included for evaluation during 'Apply'.
		rule = pcrEventLogEquals{
			expectedEventLogEntry: expectedEventLogEntry,
			expectedPcr:           expectedPcr,
			flavorID:              &flavorID,
			marker:                marker,
			excludeComponents:     defaultExcludeComponents,
			excludeLabels:         defaultExcludeLabels,
			ruleName:              constants.RulePcrEventLogEqualsExcluding,
		}
	}

	return &rule, nil
}

type pcrEventLogEquals struct {
	expectedEventLogEntry *types.EventLogEntry
	expectedPcr           *types.Pcr
	flavorID              *uuid.UUID
	marker                common.FlavorPart
	ruleName              string
	excludeTags           []string
	excludeComponents     map[string]int
	excludeLabels         map[string]int
}

// - If the PcrManifest is not present in the host manifest, raise PcrManifestMissing fault.
// - If the PcrManifest's event log is not present in the host manifest, raise PcrEventLogMissing fault.
// - Otherwise, strip out pre-defined events from the host manifest's event log (when 'excludestags' are
//   present) and then subtract 'expected' from 'actual'. If the results are not empty, raise a
//   PcrEventLogContainsUnexpectedEntries fault.
// - Also report the missing events by subtracting 'actual' from 'expected' and raising a
//   PcrEventLogMissingExpectedEntries fault.
func (rule *pcrEventLogEquals) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = rule.ruleName

	if !reflect.DeepEqual(rule.expectedEventLogEntry.PcrEventLogs, []types.EventLogCriteria{}) {
		result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
			if err != nil {
				return nil, err
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedEventLogEntry.PcrIndex), rule.expectedEventLogEntry.PcrBank))
			} else {

				// when component excludes are present, strip out the events
				if rule.excludeTags != nil {
					actualEventLog, err = rule.removeExcludedEvents(actualEventLog)
					if err != nil {
						return nil, err
					}
				}

				// now subtract out 'expected'
				unexpectedEventLogs, unexpectedFields, err := actualEventLog.Subtract(rule.expectedEventLogEntry)
				if err != nil {
					return nil, err
				}

				// if there are any remaining events, then there were unexpected entries...
				if len(unexpectedEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs))
				}

				if len(unexpectedFields.EventLogs) > 0 {
					Pi := types.PcrIndex(actualEventLog.PcrIndex)

					mismatchInfo := hvs.MismatchField{

						Name:              constants.PcrEventLogUnexpectedFields,
						Description:       fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", actualEventLog.PcrIndex, actualEventLog.PcrBank, len(unexpectedFields.PcrEventLogs)),
						PcrIndex:          &Pi,
						PcrBank:           &actualEventLog.PcrBank,
						UnexpectedEntries: unexpectedFields.EventLogs,
					}
					result.MismatchField = append(result.MismatchField, mismatchInfo)
				}

				// now, look the other way -- find events that are in actual but not expected (i.e. missing)
				missingEventLogs, missingFields, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, err
				}

				if len(missingEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEventLogs))
				}

				if len(missingFields.EventLogs) > 0 {
					Pi := types.PcrIndex(rule.expectedEventLogEntry.PcrIndex)

					mismatchInfo := hvs.MismatchField{

						Name:           constants.PcrEventLogMissingFields,
						Description:    fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank, len(missingFields.PcrEventLogs)),
						PcrIndex:       &Pi,
						PcrBank:        &rule.expectedEventLogEntry.PcrBank,
						MissingEntries: missingFields.EventLogs,
					}
					result.MismatchField = append(result.MismatchField, mismatchInfo)
				}
			}
		}
	} else {
		result.Rule.ExpectedPcr = rule.expectedPcr
		result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
			if err != nil {
				return nil, err
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank))
			} else {

				// when component excludes are present, strip out the events with the component names
				if rule.excludeComponents != nil {
					actualEventLog, err = rule.removeExcludedEvents(actualEventLog)
					if err != nil {
						return nil, err
					}
				}

				// when label exluses are present, strip out the events with the label values
				if rule.excludeLabels != nil {
					actualEventLog, err = rule.removeEventsWithLabel(actualEventLog)
					if err != nil {
						return nil, err
					}
				}

				// now subtract out 'expected'
				unexpectedEventLogs, _, err := actualEventLog.Subtract(rule.expectedEventLogEntry)
				if err != nil {
					return nil, err
				}

				// if there are any remaining events, then there were unexpected entries...
				if len(unexpectedEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs))
				}

				// now, look the other way -- find events that are in actual but not expected (i.e. missing)
				missingEventLogs, _, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, err
				}

				if len(missingEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEventLogs))
				}
			}
		}
	}

	return &result, nil
}

// Creates a new EventLogEntry without events given in excludetags

func (rule *pcrEventLogEquals) removeExcludedEvents(eventLogEntry *types.EventLogEntry) (*types.EventLogEntry, error) {

	var PcrEventLogEntry *types.EventLogEntry

	if !reflect.DeepEqual(eventLogEntry.PcrEventLogs, []types.EventLogCriteria{}) {
		var eventsWithoutComponentName []types.EventLogCriteria

		// Loop through the each eventlog and see if it contains the tag given in excludetags[]
		// and if so, do not add it to the results eventlog.
		for _, eventLog := range eventLogEntry.PcrEventLogs {

			excludeTagPresent := false

			for _, a := range rule.excludeTags {
				if eventLog.Tags != nil {
					for _, tags := range eventLog.Tags {
						if a == tags {
							excludeTagPresent = true
							break
						}
					}
				}
				if excludeTagPresent {
					break
				}
			}

			if excludeTagPresent {
				log.Debugf("Excluding the evaluation of event tyoe '%s'", eventLog.TypeName)
				continue
			}
			eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)

		}

		PcrEventLogEntry = &types.EventLogEntry{
			PcrIndex:     eventLogEntry.PcrIndex,
			PcrBank:      eventLogEntry.PcrBank,
			PcrEventLogs: eventsWithoutComponentName,
		}
	} else {
		var eventsWithoutComponentName []types.EventLog

		// Loop through the each eventlog and see if it contains a ComponentName key/value.
		// If it does, see if the ComponentName exists in the 'componentNamesToExclude' map,
		// and if so, do not add it to the results eventlog.
		for _, eventLog := range eventLogEntry.EventLogs {
			if componentName, ok := eventLog.Info["ComponentName"]; ok {
				if _, ok := rule.excludeComponents[componentName]; ok {
					log.Debugf("Excluding the evaluation of event log '%s' with component name '%s'", eventLog.Label, componentName)
					continue
				}
			}

			// Also, do not add event logs where the PackageName and PackageVendor are present
			// but empty (ex. {"Packagename":""}).
			if packageName, ok := eventLog.Info["PackageName"]; ok && len(packageName) == 0 {
				if packageVendor, ok := eventLog.Info["PackageVendor"]; ok && len(packageVendor) == 0 {
					log.Debugf("Excluding the evaluation of event log '%s' with empty package name and vendor", eventLog.Label)
					continue
				}
			}

			eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)
		}
		PcrEventLogEntry = &types.EventLogEntry{
			PcrIndex:  eventLogEntry.PcrIndex,
			PcrBank:   eventLogEntry.PcrBank,
			EventLogs: eventsWithoutComponentName,
		}
	}

	return PcrEventLogEntry, nil
}

// Creates a new EventLogEntry without events where EventLog.label matches 'label'
func (rule *pcrEventLogEquals) removeEventsWithLabel(eventLogEntry *types.EventLogEntry) (*types.EventLogEntry, error) {

	var eventsWithoutLabel []types.EventLog

	for _, eventLog := range eventLogEntry.EventLogs {
		if _, ok := rule.excludeLabels[eventLog.Label]; ok {
			log.Debugf("Excluding the evaluation of event log with label '%s'", eventLog.Label)
			continue
		}

		eventsWithoutLabel = append(eventsWithoutLabel, eventLog)
	}

	return &types.EventLogEntry{
		PcrIndex:  eventLogEntry.PcrIndex,
		PcrBank:   eventLogEntry.PcrBank,
		EventLogs: eventsWithoutLabel,
	}, nil
}
