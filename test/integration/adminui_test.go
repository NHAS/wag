package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
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

func TestAdminLoginConcurrency(t *testing.T) {
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

	goroutines := config.Values.Webserver.Lockout + 1
	successCount := make(chan int, goroutines)
	start := make(chan bool)

	var wg sync.WaitGroup

	// Launch multiple goroutines trying to use the same token
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var request adminui.LoginRequestDTO
			request.Username = adminUsername
			request.Password = fmt.Sprintf("noot%d", i)
			if goroutines == i {
				request.Password = adminPassword
			}

			b, _ := json.Marshal(request)

			<-start
			req, err := http.NewRequest(http.MethodPost, "http://"+result.ListenAddress+"/api/login", bytes.NewBuffer(b))
			if err != nil {
				return
			}

			req.Header.Set("content-type", "application/json")
			req.Header.Set("origin", "http://"+result.ListenAddress)

			resp, err := http.DefaultClient.Do(req)
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
	if total != 0 {
		t.Fatalf("expected exactly 0 successful registrations, got %d", total)
	}
}
