package data

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type UserModel struct {
	Username  string
	Mfa       string
	MfaType   string
	Locked    bool
	Enforcing bool
}

func (um *UserModel) GetID() [20]byte {
	return sha1.Sum([]byte(um.Username))
}

// Make sure that the attempts is always incremented first to stop race condition attacks
func IncrementAuthenticationAttempt(username, device string) error {
	return doSafeUpdate(context.Background(), deviceKey(username, device), func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("invalid number of users")
		}

		var userDevice Device
		err = json.Unmarshal(gr.Kvs[0].Value, &userDevice)
		if err != nil {
			return "", err
		}

		l, err := GetLockout()
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

func GetAuthenticationDetails(username, device string) (mfa, mfaType string, attempts int, locked bool, err error) {

	txn := etcd.Txn(context.Background())
	resp, err := txn.Then(clientv3.OpGet("users-"+username+"-"), clientv3.OpGet("devices-"+username+"-"+device)).Commit()
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
func SetUserLock(username string) error {
	err := doSafeUpdate(context.Background(), "users-"+username+"-", func(gr *clientv3.GetResponse) (string, error) {
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

func SetUserUnlock(username string) error {
	err := doSafeUpdate(context.Background(), "users-"+username+"-", func(gr *clientv3.GetResponse) (string, error) {
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
func IsEnforcingMFA(username string) bool {
	userResponse, err := etcd.Get(context.Background(), "users-"+username+"-")
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
func SetEnforceMFAOn(username string) error {

	return doSafeUpdate(context.Background(), "users-"+username+"-", func(gr *clientv3.GetResponse) (string, error) {
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

func SetEnforceMFAOff(username string) error {
	return doSafeUpdate(context.Background(), "users-"+username+"-", func(gr *clientv3.GetResponse) (string, error) {
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

func GetMFASecret(username string) (string, error) {
	userResponse, err := etcd.Get(context.Background(), "users-"+username+"-")
	if err != nil {
		return "", err
	}

	if len(userResponse.Kvs) != 1 {
		return "", errors.New("invalid number of users for entry")
	}

	var user UserModel
	err = json.Unmarshal(userResponse.Kvs[0].Value, &user)
	if err != nil {
		return "", err
	}

	// The webauthn "secret" needs to be used, but isnt returned to the client
	if user.Enforcing && user.MfaType != "webauthn" {
		return "", errors.New("MFA is set to enforcing, cannot reveal totp secret")
	}

	return user.Mfa, nil
}

func GetMFAType(username string) (string, error) {

	userResponse, err := etcd.Get(context.Background(), "users-"+username+"-")
	if err != nil {
		return "", err
	}

	if len(userResponse.Kvs) != 1 {
		return "", errors.New("invalid number of users for entry")
	}

	var user UserModel
	err = json.Unmarshal(userResponse.Kvs[0].Value, &user)
	if err != nil {
		return "", err
	}

	return user.MfaType, nil
}

func DeleteUser(username string) error {

	_, err := etcd.Delete(context.Background(), "users-"+username+"-", clientv3.WithPrefix())
	if err != nil {
		return err
	}

	_, err = etcd.Delete(context.Background(), "devices-"+username+"-", clientv3.WithPrefix())
	if err != nil {
		return err
	}

	return err
}

func GetUserData(username string) (u UserModel, err error) {

	userResponse, err := etcd.Get(context.Background(), "users-"+username+"-")
	if err != nil {
		return
	}

	if len(userResponse.Kvs) != 1 {
		err = errors.New("invalid number of users for entry")
		return
	}

	var user UserModel
	err = json.Unmarshal(userResponse.Kvs[0].Value, &user)
	if err != nil {
		return
	}

	return user, err
}

func GetUserDataFromAddress(address string) (u UserModel, err error) {

	refResponse, err := etcd.Get(context.Background(), "deviceref-"+address)
	if err != nil {
		return
	}

	if len(refResponse.Kvs) != 1 {
		err = errors.New("invalid number of users for entry")
		return
	}

	parts := bytes.Split(refResponse.Kvs[0].Value, []byte("-"))
	if len(parts) != 3 {
		err = errors.New("invalid number of reference key parts to extract username")
		return
	}

	// devices-username-address
	return GetUserData(string(parts[1]))
}

func SetUserMfa(username, value, mfaType string) error {

	return doSafeUpdate(context.Background(), "users-"+username+"-", func(gr *clientv3.GetResponse) (string, error) {
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

func CreateUserDataAccount(username string) (UserModel, error) {

	newUser := UserModel{
		Username: username,
	}
	b, _ := json.Marshal(&newUser)

	_, err := etcd.Put(context.Background(), "users-"+username+"-", string(b))

	return newUser, err
}

func GetAllUsers() (users []UserModel, err error) {

	response, err := etcd.Get(context.Background(), "users-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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
