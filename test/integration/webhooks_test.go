package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control"
)

func createValidWebhook() data.WebhookCreateRequestDTO {
	var newHook data.WebhookCreateRequestDTO
	newHook.ID, _ = utils.GenerateRandomHex(16)
	newHook.Action = data.CreateRegistrationToken
	newHook.AuthHeader, _ = utils.GenerateRandomHex(16)
	newHook.JsonAttributeRoles.AsUsername = "username"
	newHook.JsonAttributeRoles.AsRegistrationToken = "token"

	return newHook
}

var (
	dummyWebhookInput = struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}{
		Token:    "471605fd-52f1-4af2-9c24-04c798151633",
		Username: "toaster",
	}
)

func testWebhook(id, auth string, input []byte) error {
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8081/webhooks/"+id, bytes.NewBuffer(input))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-AUTH-HEADER", auth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != 204 {
		return fmt.Errorf("webhook endpoint responded with: %d", resp.StatusCode)

	}

	return nil
}

func TestCreateAndUseValidWebhook(t *testing.T) {

	newHook := createValidWebhook()

	err := ctrl.CreateWebhook(newHook)
	if err != nil {
		t.Fatal("should be able to create a valid webhook", err)
	}

	result, err := ctrl.GetWebhooks()
	if err != nil {
		t.Fatal(err)
	}

	if !slices.ContainsFunc(result, func(hook data.WebhookGetResponseDTO) bool {
		return hook.ID == newHook.ID
	}) {
		t.Fatal("newly created webhook was not in list of webhooks")
	}

	b, _ := json.Marshal(dummyWebhookInput)

	err = testWebhook(newHook.ID, newHook.AuthHeader, b)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for range 10 {
		// the db can take a second to pick this up, just due to the slowness of etcd, so can try a number of times
		time.Sleep(1 * time.Second)

		tokens, err := ctrl.Registrations()
		if err != nil {
			t.Fatal("Could not query list of registration tokens: ", err)
		}

		found = slices.ContainsFunc(tokens, func(token control.RegistrationResult) bool {
			return token.Token == dummyWebhookInput.Token && token.Username == dummyWebhookInput.Username
		})

		if found {
			break
		}
	}

	if !found {
		t.Fatal("could not find webhook created token")
	}

}

func TestBadAuth(t *testing.T) {

	hook := createValidWebhook()

	err := ctrl.CreateWebhook(hook)
	if err != nil {
		t.Fatal("should be able to create a valid webhook", err)
	}

	b, _ := json.Marshal(dummyWebhookInput)

	// make sure it works in general before supplying bad values
	err = testWebhook(hook.ID, hook.AuthHeader, b)
	if err != nil {
		t.Fatal(err)
	}

	// test empty
	err = testWebhook(hook.ID, "", b)
	if err == nil {
		t.Fatal("empty auth header should not be valid")
	}

	err = testWebhook(hook.ID, "waghhnnnn", b)
	if err == nil {
		t.Fatal("random auth header should not be valid")
	}

	err = testWebhook("", hook.AuthHeader, b)
	if err == nil {
		t.Fatal("empty webhook id should not be valid")
	}

}

func TestDeleteWebhook(t *testing.T) {

	hook := createValidWebhook()

	err := ctrl.CreateWebhook(hook)
	if err != nil {
		t.Fatal("should be able to create a valid webhook", err)
	}

	err = ctrl.DeleteWebhooks([]string{hook.ID})
	if err != nil {
		t.Fatal("should be able to remove webhook", err)
	}

	err = ctrl.DeleteWebhooks([]string{""})
	if err != nil {
		t.Fatal("deleting webhook that doesnt already exist is valid")
	}

	err = ctrl.DeleteWebhooks(nil)
	if err != nil {
		t.Fatal("nil value should be error")
	}
}

func TestTempWebhook(t *testing.T) {
	tempHook, err := ctrl.CreateTempWebhook()
	if err != nil {
		t.Fatal(err)
	}

	if len(tempHook.Auth) == 0 {
		t.Fatal("auth header should always be better than 0")
	}

	if len(tempHook.ID) == 0 {
		t.Fatal("ID should always be bigger than 0")
	}

	b, _ := json.Marshal(dummyWebhookInput)
	err = testWebhook(tempHook.ID, tempHook.Auth, b)
	if err != nil {
		t.Fatal("should accept data: ", err)
	}

	result, err := ctrl.GetWebhookLastRequest(tempHook.ID)
	if err != nil {
		t.Fatal("should be able to get temp webhook result: ", err)
	}

	if !bytes.Equal([]byte(result), b) {
		t.Fatal("stored value doesnt equal sent value")
	}
}
