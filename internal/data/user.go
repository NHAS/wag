package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type UserModel struct {
	Username  string
	Mfa       string `sensitive:"yes"`
	MfaType   string
	Locked    bool
	Enforcing bool
}

// IncrementAuthenticationAttempt Make sure that the attempts is always incremented first to stop race condition attacks
func (d *database) IncrementAuthenticationAttempt(username, device string) error {
	return d.doSafeUpdate(context.Background(), d.deviceKey(username, device), false, func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("invalid number of users")
		}

		var userDevice Device
		err = json.Unmarshal(gr.Kvs[0].Value, &userDevice)
		if err != nil {
			return "", err
		}

		l, err := d.GetLockout()
		if err != nil {
			return "", err
		}

		if userDevice.Attempts <= l {
			userDevice.Attempts++
		}

		b, _ := json.Marshal(userDevice)

		return string(b), nil

	})
}

func (d *database) GetAuthenticationDetails(username, device string) (mfa, mfaType string, attempts int, locked bool, err error) {

	txn := d.etcd.Txn(context.Background())
	resp, err := txn.Then(clientv3.OpGet(UsersPrefix+username+"-"), clientv3.OpGet("devices-"+username+"-"+device)).Commit()
	if err != nil {
		return
	}

	if resp.Responses[0].GetResponseRange().Count != 1 {
		err = errors.New("invalid number of user entries")
		return
	}

	userResponse := resp.Responses[0].GetResponseRange()

	if resp.Responses[1].GetResponseRange().Count != 1 {
		err = errors.New("invalid number of device entries")
		return
	}

	deviceResponse := resp.Responses[1].GetResponseRange()

	var user UserModel
	err = json.Unmarshal(userResponse.Kvs[0].Value, &user)
	if err != nil {
		return
	}

	mfa = user.Mfa
	mfaType = user.MfaType
	locked = user.Locked

	var deviceModel Device
	err = json.Unmarshal(deviceResponse.Kvs[0].Value, &deviceModel)
	if err != nil {
		return
	}

	attempts = deviceModel.Attempts

	return
}

// Disable authentication for user
func (d *database) SetUserLock(username string) error {
	err := d.doSafeUpdate(context.Background(), UsersPrefix+username+"-", false, func(gr *clientv3.GetResponse) (string, error) {
		var result UserModel
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Locked = true

		b, _ := json.Marshal(result)

		return string(b), nil

	})
	if err != nil {
		return errors.New("Unable to lock account: " + err.Error())
	}

	return nil
}

func (d *database) SetUserUnlock(username string) error {
	err := d.doSafeUpdate(context.Background(), UsersPrefix+username+"-", false, func(gr *clientv3.GetResponse) (string, error) {
		var result UserModel
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Locked = false

		b, _ := json.Marshal(result)

		return string(b), nil

	})
	if err != nil {
		return errors.New("Unable to lock account: " + err.Error())
	}

	return nil
}

// Has the user recorded their MFA details. Always read the latest value from the DB
func (d *database) IsEnforcingMFA(username string) bool {
	userResponse, err := d.etcd.Get(context.Background(), UsersPrefix+username+"-")
	if err != nil {
		// Fail closed rather than allowing a user to re-register their mfa on db error
		return true
	}

	if len(userResponse.Kvs) != 1 {
		return true
	}

	var user UserModel
	err = json.Unmarshal(userResponse.Kvs[0].Value, &user)
	if err != nil {
		return true
	}

	return user.Enforcing
}

// Stop displaying MFA secrets for user
func (d *database) SetEnforceMFAOn(username string) error {

	return d.doSafeUpdate(context.Background(), UsersPrefix+username+"-", false, func(gr *clientv3.GetResponse) (string, error) {
		var result UserModel
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Enforcing = true

		b, _ := json.Marshal(result)

		return string(b), nil

	})
}

func (d *database) SetEnforceMFAOff(username string) error {
	return d.doSafeUpdate(context.Background(), UsersPrefix+username+"-", false, func(gr *clientv3.GetResponse) (string, error) {
		var result UserModel

		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Enforcing = false

		b, _ := json.Marshal(result)

		return string(b), nil

	})
}

func (d *database) GetMFASecret(username string) (string, error) {

	user, err := get[UserModel](d.etcd, UsersPrefix+username+"-")
	if err != nil {
		return "", fmt.Errorf("failed to get user mfa secret: %w", err)
	}

	// The webauthn "secret" needs to be used, but isnt returned to the client
	if user.Enforcing && user.MfaType != "webauthn" {
		return "", errors.New("MFA is set to enforcing, will not return details (unless webauthn)")
	}

	return user.Mfa, nil
}

func (d *database) GetMFAType(username string) (string, error) {

	user, err := get[UserModel](d.etcd, UsersPrefix+username+"-")
	if err != nil {
		return "", fmt.Errorf("failed to get user mfa secret: %w", err)
	}

	return user.MfaType, nil
}

func (d *database) DeleteUser(username string) error {

	var errs []error

	_, err := d.etcd.Delete(context.Background(), UsersPrefix+username+"-", clientv3.WithPrefix())
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete user from db: %w", err))
	}

	err = d.RemoveUserAllGroups(username)
	if err != nil {
		errs = append(errs, err)
	}

	err = d.DeleteDevices(username)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (d *database) GetUserData(username string) (u UserModel, err error) {
	return get[UserModel](d.etcd, UsersPrefix+username+"-")
}

func (d *database) GetUserDataFromAddress(address string) (u UserModel, err error) {

	refResponse, err := d.etcd.Get(context.Background(), deviceRef+address)
	if err != nil {
		return
	}

	if len(refResponse.Kvs) != 1 {
		err = errors.New("invalid number of users for entry")
		return
	}

	parts := strings.Split(string(refResponse.Kvs[0].Value), "-")
	if len(parts) != 3 {
		err = errors.New("invalid number of reference key parts to extract username")
		return
	}

	// devices-username-address
	return d.GetUserData(string(parts[1]))
}

func (d *database) SetUserMfa(username, value, mfaType string) error {

	return d.doSafeUpdate(context.Background(), UsersPrefix+username+"-", false, func(gr *clientv3.GetResponse) (string, error) {
		var result UserModel
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Mfa = value
		result.MfaType = mfaType

		b, _ := json.Marshal(result)

		return string(b), nil

	})
}

func (d *database) CreateUserDataAccount(username string) (UserModel, error) {

	if strings.Contains(username, "-") {
		return UserModel{}, errors.New("usernames may not contain '-' ")
	}

	newUser := UserModel{
		Username: username,
		Mfa:      string(types.Unset),
		MfaType:  string(types.Unset),
	}

	err := set(d.etcd, UsersPrefix+username+"-", false, newUser)
	if err != nil {
		return UserModel{}, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, err
}

func (d *database) GetAllUsers() (users []UserModel, err error) {

	response, err := d.etcd.Get(context.Background(), UsersPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var user UserModel
		err := json.Unmarshal(res.Value, &user)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return
}
