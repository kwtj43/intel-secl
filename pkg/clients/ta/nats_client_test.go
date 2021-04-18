package ta

import (
	"testing"

	"github.com/google/uuid"
)

var (
	hardwareUUID = uuid.MustParse("8032632b-8fa4-e811-906e-00163566263e")
	natsServers  = []string{"nats://10.105.167.153:4222"}
)

func TestTPMQuote(t *testing.T) {

	client, err := NewNatsTAClient(natsServers, hardwareUUID)
	if err != nil {
		t.Fatalf("Could not create nats client: %+v", err)
	}

	quote, err := client.GetTPMQuote("3FvsK0fpHg5qtYuZHn1MriTMOxc=", []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}, []string{"SHA1", "SHA256"})
	if err != nil {
		t.Fatalf("Could not get tpm-quote: %+v", err)
	}

	log.Printf("Quote: %+v", quote)
}

func TestHostInfo(t *testing.T) {

	client, err := NewNatsTAClient(natsServers, hardwareUUID)
	if err != nil {
		t.Fatalf("Could not create nats client: %+v", err)
	}

	hostInfo, err := client.GetHostInfo()
	if err != nil {
		t.Fatalf("Could not get host-info: %+v", err)
	}

	t.Logf("HostInfo: %+v", hostInfo)
}

func TestAIK(t *testing.T) {

	client, err := NewNatsTAClient(natsServers, hardwareUUID)
	if err != nil {
		t.Fatalf("Could not create nats client: %+v", err)
	}

	aik, err := client.GetAIK()
	if err != nil {
		t.Fatalf("Could not get host-info: %+v", err)
	}

	t.Logf("AIK: %+v", aik)
}
