package integration

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

const validRegistrationToken = "fdf2cb00-c9bc-4d92-9631-894705c94972"

func TestRegistrationToken(t *testing.T) {
	result, err := ctrl.NewRegistration(validRegistrationToken, "toaster", "", "", 1, "")
	if err != nil {
		t.Fatal("failed to create registration token: ", err)
	}

	if result.Token != validRegistrationToken {
		t.Fatal("unequal")
	}

	if len(result.Groups) != 0 {
		t.Fatal("weirdly sized groups")
	}

	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("invalid status")
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("couldnt read body", err)
	}

	if !bytes.Contains(responseBytes, []byte("PublicKey =")) {
		t.Fatal("could not find public key within wireguard ini", string(responseBytes))
	}

	resp, err = http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("token should not be able to be used twice when 1 uses specified")
	}

}

func TestInvalidTokenLength(t *testing.T) {
	const tooShort = "too-short"

	_, err := ctrl.NewRegistration(tooShort, "toaster", "", "", 1, "")
	if err == nil {
		t.Fatal("should have failed to create token")
	}

	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + tooShort)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("Should not have been created")
	}
}
