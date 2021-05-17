package ta

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
)

var (
	defaultTimeout = 30 * time.Second
)

func NewNatsTAClient(natsServers []string, hardwareUUID uuid.UUID) (TAClient, error) {

	if len(natsServers) == 0 {
		return nil, errors.New("At least one nats-server must be provided.")
	}

	if hardwareUUID == uuid.Nil {
		return nil, errors.New("Invalid hardware uuid")
	}

	client := natsTAClient{
		natsServers:  natsServers,
		hardwareUUID: hardwareUUID,
	}

	return &client, nil
}

func (client *natsTAClient) newNatsConnection() (*nats.EncodedConn, error) {

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile("/tmp/nats-auth/certs/ca.pem")
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", "ca.pem", err)
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}

	conn, err := nats.Connect(strings.Join(client.natsServers, ","),
		nats.Secure(&tlsConfig),
		nats.UserCredentials("/tmp/nats-auth/isecl-hvs.creds"),
		nats.ErrorHandler(func(nc *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				log.Printf("NATS: Could not process subscription for subject %q: %v", s.Subject, err)
			} else {
				log.Printf("NATS: Unknown error: %v", err)
			}
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("NATS: Client disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Printf("NATS: Client reconnected")
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Printf("NATS: Client closed")
		}))

	if err != nil {
		return nil, fmt.Errorf("Failed to create nats connection: %+v", err)
	}

	encodedConn, err := nats.NewEncodedConn(conn, "json")
	if err != nil {
		return nil, fmt.Errorf("Failed to create encoded connection: %+v", err)
	}

	return encodedConn, nil
}

type natsTAClient struct {
	natsServers    []string
	natsConnection *nats.EncodedConn
	hardwareUUID   uuid.UUID
}

func (client *natsTAClient) GetHostInfo() (taModel.HostInfo, error) {
	hostInfo := taModel.HostInfo{}

	conn, err := client.newNatsConnection()
	if err != nil {
		return hostInfo, err
	}

	defer conn.Close()

	err = conn.Request(client.createSubject("host-info-request"), nil, &hostInfo, defaultTimeout)
	if err != nil {
		return hostInfo, err
	}

	return hostInfo, nil
}

func (client *natsTAClient) GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error) {

	quoteResponse := taModel.TpmQuoteResponse{}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return quoteResponse, err
	}

	quoteRequest := taModel.TpmQuoteRequest{
		Nonce:    nonceBytes,
		Pcrs:     pcrList,
		PcrBanks: pcrBankList,
	}

	conn, err := client.newNatsConnection()
	if err != nil {
		return quoteResponse, err
	}

	defer conn.Close()

	err = conn.Request(client.createSubject("quote-request"), &quoteRequest, &quoteResponse, defaultTimeout)
	if err != nil {
		return quoteResponse, err
	}

	return quoteResponse, nil
}

func (client *natsTAClient) GetAIK() ([]byte, error) {

	var aik []byte

	conn, err := client.newNatsConnection()
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	err = conn.Request(client.createSubject("aik-request"), nil, &aik, defaultTimeout)
	if err != nil {
		return nil, err
	}

	return aik, nil
}

func (client *natsTAClient) GetBindingKeyCertificate() ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (client *natsTAClient) DeployAssetTag(hardwareUUID, tag string) error {
	return errors.New("Not implemented")
}

func (client *natsTAClient) DeploySoftwareManifest(manifest taModel.Manifest) error {
	return errors.New("Not implemented")
}

func (client *natsTAClient) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	return taModel.Measurement{}, errors.New("Not implemented")
}

func (client *natsTAClient) GetBaseURL() *url.URL {
	return nil
}

func (client *natsTAClient) createSubject(request string) string {
	subject := fmt.Sprintf("trust-agent.%s.%s", client.hardwareUUID, request)
	log.Printf("Creating subject %q", subject)
	return subject
}
