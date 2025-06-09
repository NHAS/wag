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

// ListDevice if the username field is empty (""), then list all devices. Otherwise list the one device corrosponding to the set username
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

// ListSessions returns a list of active sessions across the whole cluster
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

// Take device address to remove
func (c *CtrlClient) DeleteDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/delete", form)
}

func (c *CtrlClient) LockDevice(address string) error {

	form := url.Values{}
	form.Add("address", address)

	return c.simplepost("device/lock", form)
}

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

// Take device address to remove
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

// Take device address to remove
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

func (c *CtrlClient) ListAllGroups() (groups []control.GroupData, err error) {

	response, err := c.httpClient.Get("http://unix/groups/list")
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

	err = safedecoder.Decoder(response.Body).Decode(&groups)

	return
}

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

// Take device address to remove
func (c *CtrlClient) DeleteUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/delete", form)
}

func (c *CtrlClient) LockUser(username string) error {
	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/lock", form)
}

func (c *CtrlClient) UnlockUser(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/unlock", form)
}

func (c *CtrlClient) ResetUserMFA(username string) error {

	form := url.Values{}
	form.Add("username", username)

	return c.simplepost("users/reset", form)
}

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

// Add wag rule
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

// Edit wag rule
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

// Add wag group/s
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

func (c *CtrlClient) NewRegistration(token, username, overwrite, staticIP string, uses int, groups ...string) (r control.RegistrationResult, err error) {

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

func (c *CtrlClient) Shutdown(cleanup bool) (err error) {

	form := url.Values{}
	form.Add("cleanup", fmt.Sprintf("%t", cleanup))

	return c.simplepost("shutdown", form)
}

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
