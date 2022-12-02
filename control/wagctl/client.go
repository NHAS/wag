package wagctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
)

var (
	client = http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", control.Socket)
			},
		},
	}
)

func simplepost(path string, form url.Values) error {

	response, err := client.Post("http://unix/"+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
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

// List devices, if the username field is empty (""), then list all devices. Otherwise list the one device corrosponding to the set username
func ListDevice(username string) (d []data.Device, err error) {

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

// Take device address to remove
func DeleteDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return simplepost("device/delete", form)
}

func LockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return simplepost("device/lock", form)
}

func UnlockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return simplepost("device/unlock", form)
}

func ListUsers(username string) (users []data.UserModel, err error) {

	response, err := client.Get("http://unix/users/list?username=" + url.QueryEscape(username))
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

	err = json.NewDecoder(response.Body).Decode(&users)

	return
}

// Take device address to remove
func DeleteUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return simplepost("users/delete", form)
}

func LockUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return simplepost("users/lock", form)
}

func UnlockUser(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return simplepost("users/unlock", form)
}

func ResetUserMFA(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return simplepost("users/reset", form)
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

func FirewallRules() (rules map[string]router.FirewallRules, err error) {

	response, err := client.Get("http://unix/firewall/list")
	if err != nil {
		return rules, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return rules, err
		}

		return rules, errors.New("Error: " + string(result))
	}

	err = json.NewDecoder(response.Body).Decode(&rules)
	if err != nil {
		return rules, err
	}

	return
}

func ConfigReload() error {

	response, err := client.Post("http://unix/config/reload", "text/plain", nil)
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

func GetBPFVersion() (string, error) {

	response, err := client.Get("http://unix/version/bpf")
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

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		return nil, errors.New(string(result))
	}

	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return nil, errors.New("unable to decode json: " + err.Error())
	}

	return
}

func NewRegistration(token, username, overwrite string) (r control.RegistrationResult, err error) {

	form := url.Values{}
	form.Add("username", username)
	form.Add("token", token)
	form.Add("overwrite", overwrite)

	response, err := client.Post("http://unix/registration/create", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return control.RegistrationResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return control.RegistrationResult{}, err
		}

		return control.RegistrationResult{}, errors.New(string(result))
	}

	if err := json.NewDecoder(response.Body).Decode(&r); err != nil {
		return control.RegistrationResult{}, err
	}

	return
}

func DeleteRegistration(id string) (err error) {

	form := url.Values{}
	form.Add("id", id)

	return simplepost("registration/delete", form)
}

func Shutdown(cleanup bool) (err error) {

	form := url.Values{}
	form.Add("cleanup", fmt.Sprintf("%t", cleanup))

	return simplepost("shutdown", form)
}

func PinBPF() (err error) {

	response, err := client.Get("http://unix/ebpf/pin")
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

func UnpinBPF() (err error) {

	response, err := client.Get("http://unix/ebpf/unpin")
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
