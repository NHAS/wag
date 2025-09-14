package integration

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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

func TestRegistrationTokenMultipleUses(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()
	maxUses := 3

	_, err := ctrl.NewRegistration(validRegistrationToken, "multiusedevice", "", "", maxUses, "")
	if err != nil {
		t.Fatalf("failed to create registration token: %v", err)
	}

	// Use the token multiple times up to the limit
	for i := range maxUses {
		resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("use %d should have succeeded instead, got status %d", i, resp.StatusCode)
		}
	}

	tokens, err := ctrl.Registrations()
	if err != nil {
		t.Fatal(err)
	}

	if slices.ContainsFunc(tokens, func(a control.RegistrationResult) bool {
		return a.Token == validRegistrationToken
	}) {
		t.Fatal("token should not be present after max uses")
	}

	// Try to use it one more time - should fail
	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("token should not work after exceeding max uses")
	}

}

func TestRegistrationTokenWithGroups(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()
	groups := []string{"group:nerds"}

	result, err := ctrl.NewRegistration(validRegistrationToken, "groupeddevice", "", "", 1, "", groups...)
	if err != nil {
		t.Fatalf("failed to create registration token with groups: %v", err)
	}

	// Verify groups are properly set
	if len(result.Groups) == 0 {
		t.Fatal("groups should not be empty")
	}

	if len(result.Groups) != len(groups) {
		t.Fatalf("expected %d groups, got %d", len(groups), len(result.Groups))
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
	testCases := []struct {
		name  string
		token string
	}{
		{"too short", "short"},
		{"too long", strings.Repeat("a", 1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ctrl.NewRegistration(tc.token, "unnniiuquueee"+tc.name, "", "", 1, "")
			if err == nil {
				t.Fatal("expected failure to create token with invalid length: ", tc.name, resp)
			}
		})
	}
}

func TestRegistrationTokenConcurrency(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()

	_, err := ctrl.NewRegistration(validRegistrationToken, "concurrentuser", "", "", 1, "")
	if err != nil {
		t.Fatalf("failed to create registration token: %v", err)
	}

	const goroutines = 20
	successCount := make(chan int, goroutines)
	start := make(chan bool)

	var wg sync.WaitGroup

	// Launch multiple goroutines trying to use the same token
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + validRegistrationToken)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				successCount <- 1
			} else {
				successCount <- 0
			}
		}()
	}

	// will immediately unblock all threads
	close(start)

	wg.Wait()
	close(successCount)

	// Count successful registrations
	total := 0
	for count := range successCount {
		total += count
	}

	// Only one should succeed since max uses is 1
	if total != 1 {
		t.Fatalf("expected exactly 1 successful registration, got %d", total)
	}
}

func TestRegistrationTokenSpecialCharacters(t *testing.T) {

	specialTokens := map[string]bool{
		"token-with-dashes" + makeRegistrationToken():      false,
		"token_with_underscores" + makeRegistrationToken(): false,
		"token.with.dots" + makeRegistrationToken():        false,
		"token+with+plus" + makeRegistrationToken():        false,
	}

	for token, expectError := range specialTokens {
		t.Run(fmt.Sprintf("token_%s", token), func(t *testing.T) {
			// Try to create token (may or may not be valid depending on your validation)
			_, err := ctrl.NewRegistration(token, "specialdevice", "", "", 1, "")
			if expectError {
				if err == nil {
					t.Fatal("expected to get error from token creation: ", token, "but didnt")
				}

			} else {
				if err != nil {
					t.Fatal("wasnt expecting error for token: ", token, "got", err)
				}
			}

			// Test the HTTP endpoint regardless of creation success
			resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + url.QueryEscape(token))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 && !expectError {
				t.Fatal("despite allowing creation, failed to use token: ", token)
			}
		})
	}
}

func TestRegistrationTokenDuplicates(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()

	// Create first token
	_, err := ctrl.NewRegistration(validRegistrationToken, "device1", "", "", 1, "")
	if err != nil {
		t.Fatalf("failed to create first registration token: %v", err)
	}

	// Try to create duplicate token
	_, err = ctrl.NewRegistration(validRegistrationToken, "device2", "", "", 1, "")
	if err == nil {
		t.Fatal("should not be able to create duplicate registration tokens")
	}
}

func TestRegistrationTokenInvalidHTTPMethods(t *testing.T) {
	validRegistrationToken := makeRegistrationToken()

	_, err := ctrl.NewRegistration(validRegistrationToken, "methodtestdevice", "", "", 1, "")
	if err != nil {
		t.Fatalf("failed to create registration token: %v", err)
	}

	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, "http://127.0.0.1:8081/register_device?key="+validRegistrationToken, nil)
			if err != nil {
				t.Fatal(err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// Should return method not allowed or similar error
			if resp.StatusCode == 200 {
				t.Fatalf("method %s should not be allowed", method)
			}
		})
	}
}
