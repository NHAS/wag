package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/NHAS/wag/database"
)

var (
	client = http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", controlSocket)
			},
		},
	}
)

// List devices, if the username field is empty (""), then list all devices. Otherwise list the one device corrosponding to the set username
func ListDevice(username string) (d []database.Device, err error) {

	response, err := client.Get("http://unix/device/list?username=" + url.QueryEscape(username))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		return nil, errors.New(string(result))
	}

	err = json.NewDecoder(response.Body).Decode(&d)

	return
}

func DeleteDevice(username string) error {

	form := url.Values{}
	form.Add("username", username)

	response, err := client.Post("http://unix/device/delete", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}

func LockDevice(username string) error {

	form := url.Values{}
	form.Add("username", username)

	response, err := client.Post("http://unix/device/lock", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(result))
	}

	return nil
}

func UnlockDevice(username string) error {

	form := url.Values{}
	form.Add("username", username)

	response, err := client.Post("http://unix/device/unlock", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(result))
	}

	return nil
}

func Sessions() (string, error) {

	response, err := client.Get("http://unix/device/sessions")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func FirewallRules() error {

	response, err := client.Get("http://unix/firewall/list")
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}

func ConfigReload() error {

	response, err := client.Post("http://unix/config/reload", "text/plain", nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}

func GetVersion() (string, error) {

	response, err := client.Get("http://unix/version")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func Registrations() (out map[string]string, err error) {

	response, err := client.Get("http://unix/registration/list")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return nil, err
	}

	return
}

type RegistrationResult struct {
	Token    string
	Username string
}

func NewRegistration(token, username string) (r RegistrationResult, err error) {

	form := url.Values{}
	form.Add("username", username)
	form.Add("token", token)

	response, err := client.Post("http://unix/registration/create", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return RegistrationResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return RegistrationResult{}, err
		}

		return RegistrationResult{}, errors.New(string(result))
	}

	if err := json.NewDecoder(response.Body).Decode(&r); err != nil {
		return RegistrationResult{}, err
	}

	return
}

func DeleteRegistration(id string) (err error) {

	form := url.Values{}
	form.Add("id", id)

	response, err := client.Post("http://unix/registration/delete", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}

		return errors.New(string(result))
	}

	return
}
