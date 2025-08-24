package integration

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"slices"
	"testing"

	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control"
)

func makeRegistrationToken() string {
	token, _ := utils.GenerateRandomHex(16)
	return token
}

func TestRegistrationToken(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()

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
		t.Fatal("token should not be able to be used twice when 1 uses are specified")
	}

}

func TestRegistrationTokenDelete(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()

	result, err := ctrl.NewRegistration(validRegistrationToken, "toaster2", "", "", 1, "")
	if err != nil {
		t.Fatal("failed to create registration token: ", err)
	}

	if result.Token != validRegistrationToken {
		t.Fatal("unequal")
	}

	err = ctrl.DeleteRegistration(validRegistrationToken)
	if err != nil {
		t.Fatal("token should be able to be deleted")
	}

	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("token should not be usable after deletion")
	}

	tokens, err := ctrl.Registrations()
	if err != nil {
		log.Fatal("should be able to get tokens: ", err)
	}

	if slices.ContainsFunc(tokens, func(token control.RegistrationResult) bool {
		return token.Token == validRegistrationToken
	}) {
		t.Fatal("after delete token should no longer be in list")
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
