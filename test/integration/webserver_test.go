package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

func TestChangeWebserverDetails(t *testing.T) {
	mgmtConfig, err := ctrl.GetSingleWebserverSettings(data.Management)
	if err != nil {
		t.Fatal("should be able to fetch management webserver details: ", err)
	}

	if mgmtConfig.ListenAddress != config.Values.Webserver.Management.ListenAddress {
		t.Fatal("management address not expected: ", mgmtConfig.ListenAddress, "vs", config.Values.Webserver.Management.ListenAddress)
	}

	mgmtConfig.ListenAddress = "127.0.0.1:4444"

	err = ctrl.SetSingleWebserverSetting(data.Management, mgmtConfig)
	if err != nil {
		t.Fatal("should be able to update management: ", err)
	}

	for range 10 {
		resp, err := http.Get(mgmtConfig.ListenAddress)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatal("received unexpected status code from mgmt ui after updating: ", resp.StatusCode)
		}

		break
	}
}

func TestGetInvalidWebserver(t *testing.T) {
	_, err := ctrl.GetSingleWebserverSettings("wombuously")
	if err == nil {
		t.Fatal("should fail")
	}
}

func TestGetAllWebServers(t *testing.T) {
	result, err := ctrl.GetAllWebserversSettings()
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{
		string(data.Public),
		string(data.Management),
		string(data.Tunnel),
	}

	for _, i := range expected {
		_, ok := result[i]
		if !ok {
			t.Fatal("could not find", i, "web server")
		}
	}

}
