package wagctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

type CtrlClient struct {
	httpClient http.Client
}

// NewControlClient connects to the wag unix control socket specified by socketPath
func NewControlClient(socketPath string) *CtrlClient {
	return &CtrlClient{
		httpClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
	}
}

func (c *CtrlClient) simplepost(path string, form url.Values) error {

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

// Return a list of all wireguard devicess, optionally take a username and list the devices for that specific user.
func (c *CtrlClient) ListDevice(username string) (d []data.Device, err error) {

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

	err = safedecoder.Decoder(response.Body).Decode(&d)

	return
}

// Sessions returns a list of active MFA sessions across the whole cluster
func (c *CtrlClient) Sessions() (d []data.DeviceSession, err error) {

	response, err := c.httpClient.Get("http://unix/device/sessions")
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

	err = safedecoder.Decoder(response.Body).Decode(&d)

	return
}

// Create a new device associated to a user.
func (c *CtrlClient) CreateDevice(dev control.CreateDeviceDTO) error {

	b, err := json.Marshal(dev)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Post("http://unix/devices", "application/json", bytes.NewBuffer(b))
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

// Delete a single device
func (c *CtrlClient) DeleteDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/delete", form)
}

// Device will no longer be able to send traffic to MFA routes or be able to authorise.
func (c *CtrlClient) LockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/lock", form)
}

// Device will unlock and the user will have to reauthenticate.
func (c *CtrlClient) UnlockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/unlock", form)
}

// List Admin users, or if username is supplied get details from single user
func (c *CtrlClient) ListAdminUsers(username string) (users []data.AdminUserDTO, err error) {

	response, err := c.httpClient.Get("http://unix/webadmin/list?username=" + url.QueryEscape(username))
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

	err = safedecoder.Decoder(response.Body).Decode(&users)

	return
}

// Return the admin user details
func (c *CtrlClient) GetAdminUser(username string) (user data.AdminUserDTO, err error) {

	response, err := c.httpClient.Get("http://unix/webadmin/user?username=" + url.QueryEscape(username))
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return user, err
		}

		return user, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&user)

	return
}

// AddAdminUser creates administrative user that can log in to the admin portal
func (c *CtrlClient) AddAdminUser(username, password string, changeOnFirstUser bool) error {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("change", fmt.Sprintf("%t", changeOnFirstUser))

	return c.simplepost("webadmin/add", form)
}

// Set an existing admin users password
func (c *CtrlClient) SetAdminUserPassword(username, password string) error {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)

	return c.simplepost("webadmin/reset", form)
}

func (c *CtrlClient) DeleteAdminUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("webadmin/delete", form)
}

func (c *CtrlClient) LockAdminUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("webadmin/lock", form)
}

func (c *CtrlClient) UnlockAdminUser(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("webadmin/unlock", form)
}

// Create a user with no devices in database, defaulty has unset mfa
func (c *CtrlClient) AddUser(username string) (user data.UserModel, err error) {

	b, err := json.Marshal(username)
	if err != nil {
		return user, err
	}

	response, err := c.httpClient.Post("http://unix/users", "application/json", bytes.NewBuffer(b))
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return user, err
		}

		return user, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&user)

	return
}

// If the username field is empty, list all users, otherwise list single user.
func (c *CtrlClient) ListUsers(username string) (users []data.UserModel, err error) {

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

	err = safedecoder.Decoder(response.Body).Decode(&users)

	return
}

// Fetch the users group membership
func (c *CtrlClient) UserGroups(username string) (userGroups []string, err error) {

	response, err := c.httpClient.Get("http://unix/users/groups?username=" + url.QueryEscape(username))
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

	err = safedecoder.Decoder(response.Body).Decode(&userGroups)

	return
}

// Remove user and all associated devices
func (c *CtrlClient) DeleteUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/delete", form)
}

// Lock an entire user account, all devices will be locked and unable to access MFA routes until unlocked. User will be notified.
func (c *CtrlClient) LockUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/lock", form)
}

// Unlock account, users devices will be able to login but will have to reauthenticate
func (c *CtrlClient) UnlockUser(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/unlock", form)
}

// Allow the user to re-register MFA method.
func (c *CtrlClient) ResetUserMFA(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/reset", form)
}

// Return list of currently allowed/denied and authorisation required ips and ports
func (c *CtrlClient) GetUsersAcls(username string) (acl acls.Acl, err error) {

	response, err := c.httpClient.Get("http://unix/users/acls?username=" + url.QueryEscape(username))
	if err != nil {
		return acls.Acl{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return acls.Acl{}, err
		}

		return acls.Acl{}, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&acl)
	if err != nil {
		return acls.Acl{}, err
	}

	return acl, nil
}

// A debug tool that returns a map of usernames to their respective firewall rules
func (c *CtrlClient) FirewallRules() (rules map[string]router.FirewallRules, err error) {

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

	err = safedecoder.Decoder(response.Body).Decode(&rules)
	if err != nil {
		return rules, err
	}

	return
}

// Get all acl policies defined in wag
func (c *CtrlClient) GetPolicies() (result []control.PolicyData, err error) {

	response, err := c.httpClient.Get("http://unix/config/policies/list")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return
}

// Add wag acl policy rule
func (c *CtrlClient) AddPolicy(policies control.PolicyData) error {

	policiesData, err := json.Marshal(policies)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Post("http://unix/config/policy/create", "application/json", bytes.NewBuffer(policiesData))
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

// Update a wag policy
func (c *CtrlClient) EditPolicies(policy control.PolicyData) error {

	polciesData, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Post("http://unix/config/policy/edit", "application/json", bytes.NewBuffer(polciesData))
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

func (c *CtrlClient) RemovePolicies(policyNames []string) error {

	policiesData, err := json.Marshal(policyNames)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Post("http://unix/config/policies/delete", "application/json", bytes.NewBuffer(policiesData))
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

// Get all groups on wag, this includes which users are in said groups
func (c *CtrlClient) GetGroups() (result []control.GroupData, err error) {

	response, err := c.httpClient.Get("http://unix/config/group/list")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return
}

// Create a wag group
func (c *CtrlClient) AddGroup(group control.GroupCreateData) error {

	groupData, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(group.Group, "group:") {
		return errors.New("group did not have the 'group:' prefix")
	}

	response, err := c.httpClient.Post("http://unix/config/group/create", "application/json", bytes.NewBuffer(groupData))
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

// Edit wag group members
func (c *CtrlClient) EditGroup(group control.GroupEditData) error {

	groupData, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(group.Group, "group:") {
		return errors.New("group did not have the 'group:' prefix")
	}

	response, err := c.httpClient.Post("http://unix/config/group/edit", "application/json", bytes.NewBuffer(groupData))
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

func (c *CtrlClient) RemoveGroup(groupNames []string) error {

	groupData, err := json.Marshal(groupNames)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Post("http://unix/config/group/delete", "application/json", bytes.NewBuffer(groupData))
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

// Get the settings object related to help email, etc
func (c *CtrlClient) GetGeneralSettings() (allSettings data.GeneralSettings, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/general")
	if err != nil {
		return allSettings, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return allSettings, err
		}
		return allSettings, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&allSettings)
	if err != nil {
		return allSettings, err
	}

	return allSettings, nil
}

func (c *CtrlClient) SetGeneralSettings(allSettings data.GeneralSettings) (err error) {

	settingsByte, err := json.Marshal(allSettings)
	if err != nil {
		return fmt.Errorf("unable to marshal general settings to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/general", "application/json", bytes.NewBuffer(settingsByte))
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

// Get information about what MFA methods are enabled
func (c *CtrlClient) GetLoginSettings() (allSettings data.LoginSettings, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/login")
	if err != nil {
		return allSettings, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return allSettings, err
		}
		return allSettings, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&allSettings)
	if err != nil {
		return allSettings, err
	}

	return allSettings, nil
}

func (c *CtrlClient) SetLoginSettings(allSettings data.LoginSettings) (err error) {

	settingsByte, err := json.Marshal(allSettings)
	if err != nil {
		return fmt.Errorf("unable to marshal general settings to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/login", "application/json", bytes.NewBuffer(settingsByte))
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

// Get all wag running webserver configurations, this includes if they are doing TLS and ACME
func (c *CtrlClient) GetAllWebserversSettings() (result map[string]data.WebserverConfiguration, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/webservers")
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

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Get a single web server configuration
func (c *CtrlClient) GetSingleWebserverSettings(server data.Webserver) (result data.WebserverConfiguration, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/webserver?name=" + url.QueryEscape(string(server)))
	if err != nil {
		return data.WebserverConfiguration{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return data.WebserverConfiguration{}, err
		}
		return data.WebserverConfiguration{}, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return data.WebserverConfiguration{}, err
	}

	return result, nil
}

// Update a webservers configuration, this can be used to turn on/off TLS, set domain, set listening address and more
// If ths update fails to apply the wag server will attempt to roll back the change
func (c *CtrlClient) SetSingleWebserverSetting(server data.Webserver, webConfig data.WebserverConfiguration) (err error) {
	settingsByte, err := json.Marshal(webConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal general settings to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/webserver?name="+url.QueryEscape(string(server)), "application/json", bytes.NewBuffer(settingsByte))
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

func (c *CtrlClient) GetAcmeDNS01CloudflareToken() (result data.CloudflareToken, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/cloudflare/dns01token")
	if err != nil {
		return data.CloudflareToken{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return data.CloudflareToken{}, err
		}
		return data.CloudflareToken{}, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return data.CloudflareToken{}, err
	}

	return result, nil
}

func (c *CtrlClient) SetAcmeDNS01CloudflareToken(token string) (err error) {
	settingsByte, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("unable to marshal cloudflare token to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/acme/cloudflare/dns01token", "application/json", bytes.NewBuffer(settingsByte))
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

// The ACME provider URL, i.e what is giving us our certificates
func (c *CtrlClient) GetAcmeProvider() (result string, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/acme/provider")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		return "", errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result, nil
}

// What URL should we query for getting our TLS certificates
func (c *CtrlClient) SetAcmeProvider(providerURL string) (err error) {
	settingsByte, err := json.Marshal(providerURL)
	if err != nil {
		return fmt.Errorf("unable to marshal provider URL to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/acme/provider", "application/json", bytes.NewBuffer(settingsByte))
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

func (c *CtrlClient) GetAcmeEmail() (result string, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/acme/email")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return "", err
		}
		return "", errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (c *CtrlClient) SetAcmeEmail(email string) (err error) {
	settingsByte, err := json.Marshal(email)
	if err != nil {
		return fmt.Errorf("unable to marshal acme email to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/config/settings/acme/email", "application/json", bytes.NewBuffer(settingsByte))
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

// Get global number of authentication attempts that can occur
// this applies to admin and regular users
func (c *CtrlClient) GetLockout() (lockout int, err error) {

	response, err := c.httpClient.Get("http://unix/config/settings/lockout")
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return 0, err
		}
		return 0, errors.New(string(result))
	}

	err = safedecoder.Decoder(response.Body).Decode(&lockout)
	if err != nil {
		return 0, err
	}

	return lockout, nil
}

// Get running wag instance version
func (c *CtrlClient) GetVersion() (string, error) {

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

// Return all active registration tokens
func (c *CtrlClient) Registrations() (result []control.RegistrationResult, err error) {

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

	if err := safedecoder.Decoder(response.Body).Decode(&result); err != nil {
		return nil, errors.New("unable to decode json: " + err.Error())
	}

	return
}

// Create a new registration token, the majority of these fields are optional
// The only required fields are `username` and `uses`
func (c *CtrlClient) NewRegistration(token, username, overwrite, staticIP string, uses int, tag string, groups ...string) (r control.RegistrationResult, err error) {

	if uses <= 0 {
		err = errors.New("unable to create token with <= 0 uses")
		return
	}

	form := url.Values{}
	form.Add("username", username)
	form.Add("token", token)
	form.Add("static_ip", staticIP)
	form.Add("overwrite", overwrite)
	form.Add("uses", fmt.Sprintf("%d", uses))
	form.Add("tag", tag)

	for i := range groups {
		if !strings.HasPrefix(groups[i], "group:") {
			groups[i] = "group:" + groups[i]
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

	if err := safedecoder.Decoder(response.Body).Decode(&r); err != nil {
		return control.RegistrationResult{}, err
	}

	return
}

func (c *CtrlClient) DeleteRegistration(id string) (err error) {

	form := url.Values{}
	form.Add("id", id)

	return c.simplepost("registration/delete", form)
}

// Shutdown the wag node
func (c *CtrlClient) Shutdown(cleanup bool) (err error) {

	form := url.Values{}
	form.Add("cleanup", fmt.Sprintf("%t", cleanup))

	return c.simplepost("shutdown", form)
}

// Return all error events that are stored in the etcd database
func (c *CtrlClient) GetClusterErrors() (clusterErrors []data.EventError, err error) {
	response, err := c.httpClient.Get("http://unix/clustering/errors")
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

	if err := safedecoder.Decoder(response.Body).Decode(&clusterErrors); err != nil {
		return nil, errors.New("unable to decode json: " + err.Error())
	}

	return clusterErrors, nil
}

// Get wag cluster members, this is etcd information
func (c *CtrlClient) GetClusterMembers() (clusterMembers []*membership.Member, err error) {
	response, err := c.httpClient.Get("http://unix/clustering/members")
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

	if err := safedecoder.Decoder(response.Body).Decode(&clusterMembers); err != nil {
		return nil, errors.New("unable to decode json: " + err.Error())
	}

	return clusterMembers, nil
}

// Get when the cluster member specified by `id` last wrote to a value in etcd
func (c *CtrlClient) GetClusterMemberLastPing(id string) (t time.Time, err error) {
	response, err := c.httpClient.Get("http://unix/clustering/members")
	if err != nil {
		return t, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		result, err := io.ReadAll(response.Body)
		if err != nil {
			return t, err
		}

		return t, errors.New(string(result))
	}

	if err := safedecoder.Decoder(response.Body).Decode(&t); err != nil {
		return t, errors.New("unable to decode json: " + err.Error())
	}

	return t, nil
}

// Get a raw value from the etcd cluster
func (c *CtrlClient) GetDBKey(key string) (string, error) {

	b := bytes.NewBuffer(nil)

	json.NewEncoder(b).Encode(key)

	response, err := c.httpClient.Post("http://unix/db/get", "application/json", b)
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

// Push a raw value into the etcd cluster
func (c *CtrlClient) PutDBKey(key, value string) error {

	b := bytes.NewBuffer(nil)

	var d control.PutReq
	d.Key = key
	d.Value = value

	json.NewEncoder(b).Encode(d)

	response, err := c.httpClient.Post("http://unix/db/put", "application/json", b)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return errors.New(string(result))
	}

	return nil
}

// Create a webhook that wont perform any actions but will record last request (up to 4096 bytes) for 30 mins
func (c *CtrlClient) CreateTempWebhook() (result control.TempWebhookResponseDTO, err error) {

	response, err := c.httpClient.Get("http://unix/webhooks/temp")
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		r, err := io.ReadAll(response.Body)
		if err != nil {
			return result, err
		}
		return result, errors.New(string(r))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return result, err
	}

	return result, nil
}

// Get all active webhooks, this will not include temp webhooks
func (c *CtrlClient) GetWebhooks() (result []data.WebhookGetResponseDTO, err error) {

	response, err := c.httpClient.Get("http://unix/webhooks")
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		r, err := io.ReadAll(response.Body)
		if err != nil {
			return result, err
		}
		return result, errors.New(string(r))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return result, err
	}

	return result, nil
}

// Get the last bytes posted into the webhook
func (c *CtrlClient) GetWebhookLastRequest(id string) (result string, err error) {

	response, err := c.httpClient.Get("http://unix/webhook/last_request?id=" + url.QueryEscape(id))
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		r, err := io.ReadAll(response.Body)
		if err != nil {
			return result, err
		}
		return result, errors.New(string(r))
	}

	err = safedecoder.Decoder(response.Body).Decode(&result)
	if err != nil {
		return result, err
	}

	return result, nil
}

// Create an active webhook, when this webhook is used it well do some action specified by the create request
// AuthHeader is required
func (c *CtrlClient) CreateWebhook(hook data.WebhookCreateRequestDTO) (err error) {
	settingsByte, err := json.Marshal(hook)
	if err != nil {
		return fmt.Errorf("unable to marshal webhook to json: %w", err)
	}

	response, err := c.httpClient.Post("http://unix/webhooks", "application/json", bytes.NewBuffer(settingsByte))
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

func (c *CtrlClient) DeleteWebhooks(ids []string) (err error) {
	settingsByte, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("unable to marshal webhook ids to json: %w", err)
	}

	req, err := http.NewRequest(http.MethodDelete, "http://unix/webhooks", bytes.NewBuffer(settingsByte))
	if err != nil {
		return fmt.Errorf("failed to make http request to unix socket: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(req)
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
