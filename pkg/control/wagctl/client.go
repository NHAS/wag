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

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control"
)

type ctrlClient struct {
	httpClient http.Client
}

// NewControlClient connects to the wag unix control socket specified by socketPath
func NewControlClient(socketPath string) *ctrlClient {
	return &ctrlClient{
		httpClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
	}
}

func (c *ctrlClient) simplepost(path string, form url.Values) error {

	response, err := c.httpClient.Post("http://unix/"+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
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
func (c *ctrlClient) ListDevice(username string) (d []data.Device, err error) {

	response, err := c.httpClient.Get("http://unix/device/list?username=" + url.QueryEscape(username))
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
func (c *ctrlClient) DeleteDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/delete", form)
}

func (c *ctrlClient) LockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/lock", form)
}

func (c *ctrlClient) UnlockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/unlock", form)
}

func (c *ctrlClient) ListUsers(username string) (users []data.UserModel, err error) {

	response, err := c.httpClient.Get("http://unix/users/list?username=" + url.QueryEscape(username))
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
func (c *ctrlClient) DeleteUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/delete", form)
}

func (c *ctrlClient) LockUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/lock", form)
}

func (c *ctrlClient) UnlockUser(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/unlock", form)
}

func (c *ctrlClient) ResetUserMFA(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/reset", form)
}

func (c *ctrlClient) Sessions() (out []string, err error) {

	response, err := c.httpClient.Get("http://unix/device/sessions")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &out)

	return
}

func (c *ctrlClient) FirewallRules() (rules map[string]router.FirewallRules, err error) {

	response, err := c.httpClient.Get("http://unix/firewall/list")
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

func (c *ctrlClient) ConfigReload() error {

	response, err := c.httpClient.Post("http://unix/config/reload", "text/plain", nil)
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

func (c *ctrlClient) GetVersion() (string, error) {

	response, err := c.httpClient.Get("http://unix/version")
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

func (c *ctrlClient) GetBPFVersion() (string, error) {

	response, err := c.httpClient.Get("http://unix/version/bpf")
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

func (c *ctrlClient) Registrations() (result []control.RegistrationResult, err error) {

	response, err := c.httpClient.Get("http://unix/registration/list")
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

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, errors.New("unable to decode json: " + err.Error())
	}

	return
}

func (c *ctrlClient) NewRegistration(token, username, overwrite string, groups ...string) (r control.RegistrationResult, err error) {

	form := url.Values{}
	form.Add("username", username)
	form.Add("token", token)
	form.Add("overwrite", overwrite)

	for _, group := range groups {
		if !strings.HasPrefix(group, "group:") {
			return r, errors.New("group does not have 'group:' prefix: " + group)
		}
	}

	groupsJson, err := json.Marshal(groups)
	if err != nil {
		return r, err
	}

	form.Add("groups", string(groupsJson))

	response, err := c.httpClient.Post("http://unix/registration/create", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
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

func (c *ctrlClient) DeleteRegistration(id string) (err error) {

	form := url.Values{}
	form.Add("id", id)

	return c.simplepost("registration/delete", form)
}

func (c *ctrlClient) Shutdown(cleanup bool) (err error) {

	form := url.Values{}
	form.Add("cleanup", fmt.Sprintf("%t", cleanup))

	return c.simplepost("shutdown", form)
}

func (c *ctrlClient) PinBPF() (err error) {

	response, err := c.httpClient.Get("http://unix/ebpf/pin")
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

func (c *ctrlClient) UnpinBPF() (err error) {

	response, err := c.httpClient.Get("http://unix/ebpf/unpin")
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
