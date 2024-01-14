package data

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/crypto/argon2"
)

const minPasswordLength = 14

// DTO
type AdminModel struct {
	Username  string `json:"username"`
	Attempts  int    `json:"attempts"`
	DateAdded string `json:"date_added"`
	LastLogin string `json:"last_login"`
	IP        string `json:"ip"`
	Change    bool   `json:"change"`
}

type admin struct {
	AdminModel
	Hash string
}

func generateSalt() ([]byte, error) {
	randomData := make([]byte, 16)
	_, err := rand.Read(randomData)
	if err != nil {
		return nil, err
	}

	return randomData, nil
}

func CreateAdminUser(username, password string, changeOnFirstUse bool) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password is too short for administrative console (must be greater than %d characters)", minPasswordLength)
	}

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

	newAdmin := admin{
		AdminModel: AdminModel{
			Username:  username,
			DateAdded: time.Now().Format(time.RFC3339),
			Change:    changeOnFirstUse,
		},
		Hash: base64.RawStdEncoding.EncodeToString(append(hash, salt...)),
	}

	b, _ := json.Marshal(newAdmin)

	_, err = etcd.Put(context.Background(), "admin-users-"+username, string(b))

	return err
}

func CompareAdminKeys(username, password string) error {

	wasteTime := func() {
		// Null op to stop timing discovery attacks
		salt, _ := generateSalt()

		hash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

		subtle.ConstantTimeCompare(hash, hash)
	}

	err := doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (string, bool, error) {

		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", false, err
		}

		if result.Attempts >= 5 {
			wasteTime()
			return "", false, errors.New("account locked")
		}

		rawHashSalt, err := base64.RawStdEncoding.DecodeString(result.Hash)
		if err != nil {
			return "", false, err
		}

		thisHash := argon2.IDKey([]byte(password), rawHashSalt[len(rawHashSalt)-16:], 1, 10*1024, 4, 32)

		if subtle.ConstantTimeCompare(thisHash, rawHashSalt[:len(rawHashSalt)-16]) != 1 {
			result.Attempts++

			b, _ := json.Marshal(result)

			// For this specific error we need to write the attempts to the entry
			return string(b), true, errors.New("passwords did not match")
		}

		result.Attempts = 0
		b, _ := json.Marshal(result)

		return string(b), false, nil
	})

	return err
}

// Lock admin account and make them unable to login
func SetAdminUserLock(username string) error {

	return doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (string, bool, error) {
		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", false, err
		}

		result.Attempts = 6

		result.Attempts = 0
		b, _ := json.Marshal(result)

		return string(b), false, nil

	})
}

// Unlock admin account
func SetAdminUserUnlock(username string) error {

	return doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (string, bool, error) {
		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", false, err
		}

		result.Attempts = 0

		result.Attempts = 0
		b, _ := json.Marshal(result)

		return string(b), false, nil

	})
}

func DeleteAdminUser(username string) error {

	_, err := etcd.Delete(context.Background(), "admin-users-"+username, clientv3.WithPrefix())
	if err != nil {
		return err
	}

	return err
}

func GetAdminUser(username string) (a AdminModel, err error) {

	response, err := etcd.Get(context.Background(), "admin-users-"+username)
	if err != nil {
		return a, err
	}

	if len(response.Kvs) != 1 {
		return a, errors.New("invalid number of admin users")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &a)
	return
}

func GetAllAdminUsers() (adminUsers []AdminModel, err error) {

	response, err := etcd.Get(context.Background(), "admin-users-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var admin AdminModel
		err := json.Unmarshal(res.Value, &admin)
		if err != nil {
			return nil, err
		}

		adminUsers = append(adminUsers, admin)
	}

	return
}

func SetAdminPassword(username, password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password is too short for administrative console (must be greater than %d characters)", minPasswordLength)
	}

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

	return doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (value string, onErrwrite bool, err error) {

		if len(gr.Kvs) != 1 {
			return "", false, errors.New("invalid number of admin users")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", false, err
		}

		admin.Change = false
		admin.Hash = base64.RawStdEncoding.EncodeToString(append(hash, salt...))

		b, _ := json.Marshal(admin)

		return string(b), false, nil

	})

}

func setAdminHash(username, hash string) error {
	return doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (value string, onErrwrite bool, err error) {

		if len(gr.Kvs) != 1 {
			return "", false, errors.New("invalid number of admin users")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", false, err
		}

		admin.Change = false
		admin.Hash = hash

		b, _ := json.Marshal(admin)

		return string(b), false, nil

	})
}

func SetLastLoginInformation(username, ip string) error {
	return doSafeUpdate(context.Background(), "admin-users-"+username, false, func(gr *clientv3.GetResponse) (value string, onErrwrite bool, err error) {

		if len(gr.Kvs) != 1 {
			return "", false, errors.New("invalid number of admin users")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", false, err
		}

		admin.LastLogin = time.Now().Format(time.RFC3339)
		admin.IP = ip

		b, _ := json.Marshal(admin)

		return string(b), false, nil

	})

}
