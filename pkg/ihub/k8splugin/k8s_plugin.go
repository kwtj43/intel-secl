/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package k8splugin

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/util"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/k8s"
	vsPlugin "github.com/intel-secl/intel-secl/v3/pkg/ihub/attestationPlugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	types "github.com/intel-secl/intel-secl/v3/pkg/ihub/model"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/k8s"

	"io/ioutil"
	"net/http"
	"net/url"

	commonLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"

	"github.com/Waterdrips/jwt-go"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"encoding/base64"
)

//KubernetesDetails for getting hosts and updating CRD
type KubernetesDetails struct {
	Config             *config.Configuration
	AuthToken          string
	HostDetailsMap     map[string]types.HostDetails
	PrivateKey         crypto.PrivateKey
	PublicKeyBytes     []byte
	K8sClient          *k8s.Client
	TrustedCAsStoreDir string
	SamlCertFilePath   string
}

var log = commonLog.GetDefaultLogger()

//GetHosts Getting Hosts From Kubernetes
func GetHosts(k8sDetails *KubernetesDetails) error {
	log.Trace("k8splugin/k8s_plugin:GetHosts() Entering")
	defer log.Trace("k8splugin/k8s_plugin:GetHosts() Leaving")
	conf := k8sDetails.Config
	urlPath := conf.Endpoint.URL + constants.KubernetesNodesAPI
	log.Debugf("k8splugin/k8s_plugin:GetHosts() URL to get the Hosts : %s", urlPath)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Unable to parse the url")
	}

	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in getting the Hosts from kubernetes")
	}

	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in Reading the Response")
	}

	var hostResponse model.HostResponse
	err = json.Unmarshal(body, &hostResponse)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in Unmarshaling the response")
	}

	hostDetailMap := make(map[string]types.HostDetails)

	for _, items := range hostResponse.Items {

		isMaster := false

		for _, taints := range items.Spec.Taints {
			if taints.Key == "node-role.kubernetes.io/master" {
				isMaster = true
				break
			}
		}
		if !isMaster {
			var hostDetails types.HostDetails
			sysID := items.Status.NodeInfo.SystemID
			hostDetails.HostID, _ = uuid.Parse(sysID)

			for _, addr := range items.Status.Addresses {

				if addr.Type == "InternalIP" {
					hostDetails.HostIP = addr.Address
				}

				if addr.Type == "Hostname" {
					hostDetails.HostName = addr.Address
				}
			}

			hostDetailMap[hostDetails.HostIP] = hostDetails
		}

	}
	k8sDetails.HostDetailsMap = hostDetailMap
	return nil
}

//FilterHostReports Get Filtered Host Reports from HVS
func FilterHostReports(k8sDetails *KubernetesDetails, hostDetails *types.HostDetails, trustedCaDir, samlCertPath string) error {

	log.Trace("k8splugin/k8s_plugin:FilterHostReports() Entering")
	defer log.Trace("k8splugin/k8s_plugin:FilterHostReports() Leaving")

	samlReport, err := vsPlugin.GetHostReports(hostDetails.HostID.String(), k8sDetails.Config, trustedCaDir, samlCertPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:FilterHostReports() : Error in getting the host report")
	}

	trustMap := make(map[string]string)
	hardwareFeaturesMap := make(map[string]string)
	assetTagsMap := make(map[string]string)

	for _, as := range samlReport.Attribute {

		if strings.HasPrefix(as.Name, "TAG") {
			assetTagsMap[as.Name] = as.AttributeValue
		}
		if strings.HasPrefix(as.Name, "TRUST") {
			trustMap[as.Name] = as.AttributeValue
		}
		if strings.HasPrefix(as.Name, "FEATURE") {
			hardwareFeaturesMap[as.Name] = as.AttributeValue
		}

	}

	log.Debug("k8splugin/k8s_plugin:FilterHostReports() Setting Values to Host")

	overAllTrust, _ := strconv.ParseBool(trustMap["TRUST_OVERALL"])
	hostDetails.AssetTags = assetTagsMap
	hostDetails.Trust = trustMap
	hostDetails.HardwareFeatures = hardwareFeaturesMap
	hostDetails.Trusted = overAllTrust
	hostDetails.ValidTo = samlReport.Subject.NotOnOrAfter

	return nil
}

//GetSignedTrustReport Creates a Signed trust-report based on the host details
func GetSignedTrustReport(hostList model.Host, k8sDetails *KubernetesDetails, attestationType string) (string, error) {
	log.Trace("k8splugin/k8s_plugin:GetSignedTrustReport() Entering")
	defer log.Trace("k8splugin/k8s_plugin:GetSignedTrustReport() Leaving")

	hash := sha1.New()
	_, err := hash.Write(k8sDetails.PublicKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "k8splugin/k8s_plugin:GetSignedTrustReport() : Error in getting digest of Public key")
	}
	sha1Hash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	var token *jwt.Token
	if attestationType == "HVS" {
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, model.HvsHostTrustReport{
			AssetTags:        hostList.AssetTags,
			HardwareFeatures: hostList.HardwareFeatures,
			Trusted:          hostList.Trusted,
			HvsTrustValidTo:  *hostList.HvsTrustValidTo,
		})
	} else if attestationType == "SGX" {
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, model.SgxHostTrustReport{
			SgxSupported:    hostList.SgxSupported,
			SgxEnabled:      hostList.SgxEnabled,
			FlcEnabled:      hostList.FlcEnabled,
			EpcSize:         hostList.EpcSize,
			TcbUpToDate:     hostList.TcbUpToDate,
			SgxTrustValidTo: *hostList.SgxTrustValidTo,
		})
	}

	token.Header["kid"] = sha1Hash

	// Create the JWT string
	tokenString, err := token.SignedString(k8sDetails.PrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "k8splugin/k8s_plugin:GetSignedTrustReport() : Error in Getting the signed token")
	}

	return tokenString, nil

}

//UpdateCRD Updates the Kubernetes CRD with details from the host report
func UpdateCRD(k8sDetails *KubernetesDetails) error {

	log.Trace("k8splugin/k8s_plugin:UpdateCRD() Entering")
	defer log.Trace("k8splugin/k8s_plugin:UpdateCRD() Leaving")
	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Unable to parse the url")
	}
	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in fetching the kubernetes CRD")
	}
	var crdResponse model.CRD
	if res.StatusCode == http.StatusOK {
		defer func() {
			derr := res.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing response")
			}
		}()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Reading Response body")
		}

		err = json.Unmarshal(body, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Unmarshalling the CRD Reponse")
		}

		log.Debug("k8splugin/k8s_plugin:UpdateCRD() PUT Call to be made")

		crdResponse.Spec.HostList, err = populateHostDetailsInCRD(k8sDetails)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error populating crd")
		}
		err = PutCRD(k8sDetails, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Updating CRD")
		}
	} else {
		log.Debug("k8splugin/k8s_plugin:UpdateCRD() POST Call to be made")

		crdResponse.APIVersion = constants.KubernetesCRDAPIVersion
		crdResponse.Kind = constants.KubernetesCRDKind
		crdResponse.Metadata.Name = crdName
		crdResponse.Metadata.Namespace = constants.KubernetesMetaDataNameSpace
		crdResponse.Spec.HostList, err = populateHostDetailsInCRD(k8sDetails)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error populating crd")
		}
		log.Debug("k8splugin/k8s_plugin:UpdateCRD() Printing the spec hostList : ", crdResponse.Spec.HostList)
		err := PostCRD(k8sDetails, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in posting CRD")
		}

	}
	return nil
}

func populateHostDetailsInCRD(k8sDetails *KubernetesDetails) ([]model.Host, error) {
	config := k8sDetails.Config
	var hostList []model.Host

	for key := range k8sDetails.HostDetailsMap {

		reportHostDetails := k8sDetails.HostDetailsMap[key]
		var host model.Host
		host.HostName = reportHostDetails.HostName
		t := time.Now().UTC()
		host.Updated = new(time.Time)
		*host.Updated = t
		if config.AttestationService.AttestationType == "HVS" {
			host.AssetTags = reportHostDetails.AssetTags
			host.HardwareFeatures = reportHostDetails.HardwareFeatures
			host.Trusted = new(bool)
			*host.Trusted = reportHostDetails.Trusted
			host.HvsTrustValidTo = new(time.Time)
			*host.HvsTrustValidTo = reportHostDetails.ValidTo
			signedtrustReport, err := GetSignedTrustReport(host, k8sDetails, "HVS")
			if err != nil {
				return nil, errors.Wrap(err, "k8splugin/k8s_plugin:populateHostDetailsInCRD() : Error in Getting SignedTrustReport")
			}
			host.HvsSignedTrustReport = signedtrustReport

		} else if config.AttestationService.AttestationType == "SGX" {
			host.EpcSize = strings.Replace(reportHostDetails.EpcSize, " ", "", -1)
			host.FlcEnabled = strconv.FormatBool(reportHostDetails.FlcEnabled)
			host.SgxEnabled = strconv.FormatBool(reportHostDetails.SgxEnabled)
			host.SgxSupported = strconv.FormatBool(reportHostDetails.SgxSupported)
			host.TcbUpToDate = strconv.FormatBool(reportHostDetails.TcbUpToDate)
			host.SgxTrustValidTo = new(time.Time)
			*host.SgxTrustValidTo = reportHostDetails.ValidTo
			signedtrustReport, err := GetSignedTrustReport(host, k8sDetails, "SGX")
			if err != nil {
				return nil, errors.Wrap(err, "k8splugin/k8s_plugin:populateHostDetailsInCRD() : Error in Getting SignedTrustReport")
			}
			host.SgxSignedTrustReport = signedtrustReport
		}

		hostList = append(hostList, host)
	}
	return hostList, nil
}

//PutCRD PUT request call to update existing CRD
func PutCRD(k8sDetails *KubernetesDetails, crd *model.CRD) error {

	log.Trace("k8splugin/k8s_plugin:PutCRD() Entering")
	defer log.Trace("k8splugin/k8s_plugin:PutCRD() Leaving")

	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	crdJson, err := json.Marshal(crd)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() Error in Creating JSON object")
	}

	payload := bytes.NewReader(crdJson)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() : Unable to parse the url")
	}

	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method:            "PUT",
		URL:               parsedUrl,
		Body:              payload,
		AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
	})

	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() Error in creating CRD")
	}

	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()

	return nil
}

//PostCRD POST request call to create new CRD
func PostCRD(k8sDetails *KubernetesDetails, crd *model.CRD) error {

	log.Trace("k8splugin/k8s_plugin:PostCRD() Starting")
	defer log.Trace("k8splugin/k8s_plugin:PostCRD() Leaving")
	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	crdJSON, err := json.Marshal(crd)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PostCRD(): Error in Creating JSON object")
	}
	payload := bytes.NewReader(crdJSON)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PostCRD() : Unable to parse the url")
	}

	_, err = k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method:            "POST",
		URL:               parsedUrl,
		Body:              payload,
		AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
	})

	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin: PostCRD() : Error in creating CRD")
	}

	return nil
}

//SendDataToEndPoint pushes host trust data to Kubernetes
func SendDataToEndPoint(kubernetes KubernetesDetails) error {

	log.Trace("k8splugin/k8s_plugin:SendDataToEndPoint() Entering")
	defer log.Trace("k8splugin/k8s_plugin:SendDataToEndPoint() Leaving")

	var sgxData types.PlatformDataSGX

	err := GetHosts(&kubernetes)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:SendDataToEndPoint() Error in getting the Hosts from kubernetes")
	}

	if kubernetes.Config.AttestationService.AttestationType == "HVS" {
		for key := range kubernetes.HostDetailsMap {
			hostDetails := kubernetes.HostDetailsMap[key]
			err := FilterHostReports(&kubernetes, &hostDetails, kubernetes.TrustedCAsStoreDir, kubernetes.SamlCertFilePath)
			if err != nil {
				log.WithError(err).Error("k8splugin/k8s_plugin:SendDataToEndPoint() Error in Filtering Report for Hosts")
				//host doesn't exist remove from the map
				delete(kubernetes.HostDetailsMap, key)
				continue
			}
			kubernetes.HostDetailsMap[key] = hostDetails
		}
	} else if kubernetes.Config.AttestationService.AttestationType == "SGX" {
		for key := range kubernetes.HostDetailsMap {
			hostDetails := kubernetes.HostDetailsMap[key]
			platformData, err := vsPlugin.GetHostPlatformData(hostDetails.HostName, kubernetes.Config, kubernetes.TrustedCAsStoreDir)
			if err != nil {
				log.Infof("k8splugin/k8s_plugin:SendDataToEndPoint() Host %s doesn't exist in SHVS: removing from map", hostDetails.HostID)
				//host doesn't exist remove from the map
				delete(kubernetes.HostDetailsMap, key)
				continue
			}

			err = json.Unmarshal(platformData, &sgxData)
			if err != nil {
				log.WithError(err).Error("k8splugin/k8s_plugin:SendDataToEndPoint() SGX Platform data unmarshal failed")
				continue
			}

			// need to validate contents of EpcSize
			if !regexp.MustCompile(constants.RegexEpcSize).MatchString(sgxData[0].EpcSize) {
				log.WithError(err).Error("k8splugin/k8s_plugin:SendDataToEndPoint() Invalid EPC Size value")
				continue
			}
			hostDetails.EpcSize = sgxData[0].EpcSize
			hostDetails.FlcEnabled = sgxData[0].FlcEnabled
			hostDetails.SgxEnabled = sgxData[0].SgxEnabled
			hostDetails.SgxSupported = sgxData[0].SgxSupported
			hostDetails.TcbUpToDate = sgxData[0].TcbUpToDate
			util.EvaluateValidTo(sgxData[0].ValidTo, kubernetes.Config.PollIntervalMinutes)
			hostDetails.ValidTo = sgxData[0].ValidTo
			kubernetes.HostDetailsMap[key] = hostDetails
		}
	} else {
		return errors.New("k8splugin/k8s_plugin:SendDataToEndPoint() Given Attestation type is invalid")
	}

	if len(kubernetes.HostDetailsMap) > 0 {
		err = UpdateCRD(&kubernetes)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:SendDataToEndPoint() Error in Updating CRDs for Kubernetes")
		}
	}
	return nil
}
