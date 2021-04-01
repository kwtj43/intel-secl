/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/k8s"
	openstackClient "github.com/intel-secl/intel-secl/v3/pkg/clients/openstack"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

//TenantConnection is a setup task for setting up the connection to the Tenant
type TenantConnection struct {
	TenantConfig  *config.Endpoint
	ConsoleWriter io.Writer
}

// Run will run the tenant Connection setup task, but will skip if Validate() returns no errors
func (tenantConnection TenantConnection) Run() error {
	fmt.Fprintln(tenantConnection.ConsoleWriter, "Setting up Tenant Connection ...")

	endPointType := viper.GetString("tenant")
	if endPointType == "" {
		return errors.New("tasks/tenant_connection:Run() TENANT is not defined in environment")
	}

	tenantConf := tenantConnection.TenantConfig
	tenantConf.Type = endPointType

	if endPointType == constants.OpenStackTenant {

		openstackPlacementUrl := viper.GetString("openstack-placement-url")
		openstackAuthUrl := viper.GetString("openstack-auth-url")
		openstackUserName := viper.GetString("openstack-username")
		openstackPassword := viper.GetString("openstack-password")

		if openstackPlacementUrl == "" {
			return errors.New("tasks/tenant_connection:Run() OPENSTACK_PLACEMENT_URL is not defined in environment")
		}

		if openstackAuthUrl == "" {
			return errors.New("tasks/tenant_connection:Run() OPENSTACK_AUTH_URL is not defined in environment")
		}

		if openstackUserName == "" {
			return errors.New("tasks/tenant_connection:Run() OPENSTACK_USERNAME is not defined in environment")
		}

		if openstackPassword == "" {
			return errors.New("tasks/tenant_connection:Run() OPENSTACK_PASSWORD is not defined in environment")
		}

		if _, err := url.Parse(openstackPlacementUrl); err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:Run() OPENSTACK_PLACEMENT_URL is invalid")
		}

		if _, err := url.Parse(openstackAuthUrl); err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:Run() OPENSTACK_AUTH_URL is invalid")
		}

		if !strings.HasSuffix(openstackPlacementUrl, "/") {
			openstackPlacementUrl += "/"
		}

		if !strings.HasSuffix(openstackAuthUrl, "/") {
			openstackAuthUrl += "/"
		}
		openstackAuthUrl += constants.OpenStackAuthenticationAPI

		tenantConf.URL = openstackPlacementUrl
		tenantConf.AuthURL = openstackAuthUrl
		tenantConf.UserName = openstackUserName
		tenantConf.Password = openstackPassword

	} else if endPointType == constants.K8sTenant {

		k8sURL := viper.GetString("kubernetes-url")
		k8sCRDName := viper.GetString("kubernetes-crd")
		k8sToken := viper.GetString("kubernetes-token")
		k8sCertFileSrc := viper.GetString("kubernetes-cert-file")
		k8sCertFile := constants.DefaultK8SCertFile

		if k8sURL == "" {
			return errors.New("tasks/tenant_connection:Run() KUBERNETES_URL is not defined in environment")
		}

		if k8sToken == "" {
			return errors.New("tasks/tenant_connection:Run() KUBERNETES_TOKEN is not defined in environment")
		}

		if k8sCRDName == "" {
			k8sCRDName = constants.KubernetesCRDName
			fmt.Fprintln(tenantConnection.ConsoleWriter, "KUBERNETES_CRD is not defined in environment, default CRD name set")
		}

		if k8sCertFileSrc == "" {
			return errors.New("tasks/tenant_connection:Run() KUBERNETES_CERT_FILE is not defined in environment")
		}
		if _, err := os.Stat(k8sCertFileSrc); os.IsNotExist(err) {
			return errors.Wrapf(err, "tasks/tenant_connection:Run() certificate file %s does not exist", k8sCertFileSrc)
		}
		// at this point if k8sCertFileSrc is not same as default, lets copy to default
		if k8sCertFileSrc != k8sCertFile {
			// lets try to copy the file now. If copy does not succeed return the file copy error
			if err := cos.Copy(k8sCertFileSrc, k8sCertFile); err != nil {
				return errors.Wrap(err, "tasks/tenant_connection:Run() failed to copy file")
			}
			// set permissions so that non root users can read the copied file
			if err := os.Chmod(k8sCertFile, 0644); err != nil {
				return errors.Wrapf(err, "tasks/tenant_connection:Run() could not apply permissions to %s", k8sCertFile)
			}
		}

		tenantConf.URL = k8sURL
		tenantConf.CRDName = k8sCRDName
		tenantConf.Token = k8sToken
		tenantConf.CertFile = k8sCertFile

	} else {
		return errors.Errorf("tasks/tenant_connection:Run() Endpoint type '%s' is not supported", endPointType)
	}

	return nil
}

// Validate checks whether or not the tenant Connection setup task was completed successfully
func (tenantConnection TenantConnection) Validate() error {
	conf := tenantConnection.TenantConfig
	if conf.URL == "" || (conf.Type != constants.OpenStackTenant && conf.Type != constants.K8sTenant) {
		return errors.New("tasks/tenant_connection:Validate() Endpoint Connection: URL & Type is not set")
	} else if conf.Type == constants.OpenStackTenant && conf.AuthURL == "" && conf.UserName == "" && conf.Password == "" {
		return errors.New("tasks/tenant_connection:Validate() Endpoint Connection: OpenStack credentials are not set ")
	} else if conf.Type == constants.K8sTenant && conf.CRDName == "" && conf.Token == "" && conf.CertFile == "" {
		return errors.New("tasks/tenant_connection:Validate() Endpoint Connection: K8s credentials are not set ")
	}

	//validating the service url
	return tenantConnection.validateService()
}

//validates the tenant service connection is successful or not by hitting the service url's
func (tenantConnection TenantConnection) validateService() error {

	conf := tenantConnection.TenantConfig
	if conf.Type == constants.OpenStackTenant {

		authURL, err := url.Parse(conf.AuthURL)
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Unable to parse the auth URL")
		}

		apiURL, err := url.Parse(conf.URL)
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Unable to parse the api URL")
		}

		_, err = openstackClient.NewOpenstackClient(authURL, apiURL, conf.UserName, conf.Password, "")
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Error Initializing the OpenStack client")
		}
		fmt.Fprintln(tenantConnection.ConsoleWriter, "OpenStack Connection is successful")

	} else {

		parsedUrl, err := url.Parse(conf.URL)
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Unable to parse the url")
		}

		parsedRequestURL, err := url.Parse(conf.URL + constants.KubernetesNodesAPI)
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Unable to parse the api url")
		}

		//Passing CertPath as empty since the certificate might not have been exchanged.
		k8sClient, err := k8s.NewK8sClient(parsedUrl, conf.Token, "")
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Error Initializing the Kubernetes client")
		}

		res, err := k8sClient.SendRequest(&k8s.RequestParams{
			Method: "GET",
			URL:    parsedRequestURL,
			Body:   nil,
		})
		if err != nil {
			return errors.Wrap(err, "tasks/tenant_connection:validateService() : Error in getting the response from kubernetes")
		}

		if res.StatusCode == 200 {
			fmt.Fprintln(tenantConnection.ConsoleWriter, "Kubernetes connection is successful")
		}
	}

	return nil
}

func (tenantConnection TenantConnection) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"TENANT": "Type of Tenant Service (OpenStack or Kubernetes)",
	}

	var k8sEnv = map[string]string{
		"KUBERNETES_URL":       "URL for Kubernetes deployment",
		"KUBERNETES_CRD":       "CRD Name for Kubernetes deployment",
		"KUBERNETES_TOKEN":     "Token for Kubernetes deployment",
		"KUBERNETES_CERT_FILE": "Certificate path for Kubernetes deployment",
	}

	var opsEnv = map[string]string{
		"OPENSTACK_AUTH_URL":      "Keystone API endpoint for OpenStack deployment",
		"OPENSTACK_PLACEMENT_URL": "Placement API endpoint for OpenStack deployment",
		"OPENSTACK_USERNAME":      "UserName for OpenStack deployment",
		"OPENSTACK_PASSWORD":      "Password for OpenStack deployment",
	}

	setup.PrintEnvHelp(w, "Following environment variables are required for tenant-service-connection setup:", "", envHelp)
	setup.PrintEnvHelp(w, "Following environment variables are required for Kubernetes tenant: ", "", k8sEnv)
	setup.PrintEnvHelp(w, "Following environment variables are required for OpenStack tenant:", "", opsEnv)
	fmt.Fprintln(w, "")
}

func (tenantConnection TenantConnection) SetName(n, e string) {}
