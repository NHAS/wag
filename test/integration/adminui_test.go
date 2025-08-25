package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/NHAS/wag/adminui"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

func TestUsualLogin(t *testing.T) {

	result, err := ctrl.GetSingleWebserverSettings(data.Management)
	if err != nil {
		t.Fatal(err)
	}

	const (
		adminUsername = "test_admin_login"
		adminPassword = "893394d0-e040-4a66-8981-d7ee621bd134"
	)
	err = ctrl.AddAdminUser(adminUsername, adminPassword, false)
	if err != nil {
		t.Fatal(err)
	}

	var request adminui.LoginRequestDTO
	request.Username = adminUsername
	request.Password = adminPassword

	b, _ := json.Marshal(request)

	req, err := http.NewRequest(http.MethodPost, "http://"+result.ListenAddress+"/api/login", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", "http://"+result.ListenAddress)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		r, err := io.ReadAll(resp.Body)
		t.Fatal("expected to login: ", resp.StatusCode, string(r), err)
	}

}

func TestBadPassword(t *testing.T) {

	result, err := ctrl.GetSingleWebserverSettings(data.Management)
	if err != nil {
		t.Fatal(err)
	}

	const (
		adminUsername = "test_admin_login"
		adminPassword = "893394d0-e040-4a66-8981-d7ee621bd134"
	)
	err = ctrl.AddAdminUser(adminUsername, adminPassword, false)
	if err != nil {
		t.Fatal(err)
	}

	var request adminui.LoginRequestDTO
	request.Username = adminUsername
	request.Password = "noot"

	b, _ := json.Marshal(request)

	req, err := http.NewRequest(http.MethodPost, "http://"+result.ListenAddress+"/api/login", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", "http://"+result.ListenAddress)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("unexpected login")
	}

}

func TestLockout(t *testing.T) {

	result, err := ctrl.GetSingleWebserverSettings(data.Management)
	if err != nil {
		t.Fatal(err)
	}

	const (
		adminUsername = "test_admin_login_lockout"
		adminPassword = "893394d0-e040-4a66-8981-d7ee621bd134"
	)
	err = ctrl.AddAdminUser(adminUsername, adminPassword, false)
	if err != nil {
		t.Fatal(err)
	}

	var request adminui.LoginRequestDTO
	request.Username = adminUsername
	request.Password = "noot"

	b, _ := json.Marshal(request)

	for range config.Values.Webserver.Lockout + 1 {

		req, err := http.NewRequest(http.MethodPost, "http://"+result.ListenAddress+"/api/login", bytes.NewBuffer(b))
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("content-type", "application/json")
		req.Header.Set("origin", "http://"+result.ListenAddress)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			t.Fatal("unexpected login")
		}
	}

	request.Username = adminUsername
	request.Password = adminPassword

	b, _ = json.Marshal(request)

	req, err := http.NewRequest(http.MethodPost, "http://"+result.ListenAddress+"/api/login", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("origin", "http://"+result.ListenAddress)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("unexpected login")
	}
}
