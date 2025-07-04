package data

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/crypto/argon2"
)

const (
	minPasswordLength = 14
	saltLength        = 8
	LocalUser         = "local"
	OidcUser          = "oidc"

	AdminUsersKey = "admin-users-"
)

// DTO
type AdminUserDTO struct {
	Type      string `json:"user_type"`
	Username  string `json:"username"`
	Attempts  int    `json:"attempts"`
	DateAdded string `json:"date_added"`
	LastLogin string `json:"last_login"`
	IP        string `json:"ip"`
	Change    bool   `json:"change"`
	OidcGUID  string `json:"oidc_guid"`
}

type admin struct {
	AdminUserDTO
	Hash string
}

func IncrementAdminAuthenticationAttempt(username string) error {
	return doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("invalid number of admin keys")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", err
		}

		l, err := GetLockout()
		if err != nil {
			return "", err
		}

		if admin.Attempts < l {
			admin.Attempts++
		}

		b, _ := json.Marshal(admin)

		return string(b), nil

	})
}

func CreateLocalAdminUser(username, password string, changeOnFirstUse bool) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password is too short for administrative console (must be greater than %d characters)", minPasswordLength)
	}

	salt, err := utils.GenerateRandomHex(saltLength)
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

	newAdmin := admin{
		AdminUserDTO: AdminUserDTO{
			Type:      LocalUser,
			Username:  username,
			DateAdded: time.Now().Format(time.RFC3339),
			Change:    changeOnFirstUse,
		},
		Hash: base64.RawStdEncoding.EncodeToString(append(hash, salt...)),
	}

	b, _ := json.Marshal(newAdmin)

	_, err = etcd.Put(context.Background(), AdminUsersKey+username, string(b))

	return err
}

func CreateOidcAdminUser(username, guid string) (AdminUserDTO, error) {

	newAdmin := admin{
		AdminUserDTO: AdminUserDTO{
			Type:      OidcUser,
			OidcGUID:  guid,
			Username:  username,
			DateAdded: time.Now().Format(time.RFC3339),
		},
		Hash: "",
	}

	b, _ := json.Marshal(newAdmin)

	_, err := etcd.Put(context.Background(), AdminUsersKey+guid, string(b))

	return newAdmin.AdminUserDTO, err
}

func CompareAdminKeys(username, password string) error {

	wasteTime := func() {
		// Null op to stop timing discovery attacks

		salt, _ := utils.GenerateRandomHex(saltLength)

		hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

		subtle.ConstantTimeCompare(hash, hash)
	}

	err := doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (string, error) {

		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		lockout, err := GetLockout()
		if err != nil {
			return "", err
		}
		if result.Attempts >= lockout {
			wasteTime()
			return "", errors.New("account locked")
		}

		if result.Type == "" {
			result.Type = LocalUser
		}

		if result.Type == OidcUser {
			return "", errors.New("oidc users cannot sign in with compare admin keys")
		}

		rawHashSalt, err := base64.RawStdEncoding.DecodeString(result.Hash)
		if err != nil {
			return "", err
		}

		if len(rawHashSalt) < saltLength*2 {
			return "", errors.New("user has was not large enough to contain salt")
		}

		salt := rawHashSalt[len(rawHashSalt)-saltLength*2:]
		expectedHash := rawHashSalt[:len(rawHashSalt)-saltLength*2]

		thisHash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

		if subtle.ConstantTimeCompare(thisHash, expectedHash) != 1 {
			return "", errors.New("passwords did not match")
		}

		result.Attempts = 0
		b, _ := json.Marshal(result)

		return string(b), nil
	})

	return err
}

// Lock admin account and make them unable to login
func SetAdminUserLock(username string) error {

	return doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (string, error) {
		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Attempts, err = GetLockout()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(result)

		return string(b), nil

	})
}

// Unlock admin account
func SetAdminUserUnlock(username string) error {

	return doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (string, error) {
		var result admin
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.Attempts = 0
		b, _ := json.Marshal(result)

		return string(b), nil

	})
}

func DeleteAdminUser(username string) error {

	_, err := etcd.Delete(context.Background(), AdminUsersKey+username, clientv3.WithPrefix())
	if err != nil {
		return err
	}

	return err
}

func GetAdminUser(id string) (a AdminUserDTO, err error) {

	response, err := etcd.Get(context.Background(), AdminUsersKey+id)
	if err != nil {
		return a, err
	}

	if len(response.Kvs) != 1 {
		return a, errors.New("invalid number of admin users")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &a)
	return
}

func GetAllAdminUsers() (adminUsers []AdminUserDTO, err error) {

	response, err := etcd.Get(context.Background(), AdminUsersKey, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var admin AdminUserDTO
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

	salt, err := utils.GenerateRandomHex(saltLength)
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

	return doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("invalid number of admin users")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", err
		}

		admin.Change = false
		admin.Hash = base64.RawStdEncoding.EncodeToString(append(hash, salt...))

		b, _ := json.Marshal(admin)

		return string(b), nil

	})

}

func SetLastLoginInformation(username, ip string) error {
	return doSafeUpdate(context.Background(), AdminUsersKey+username, false, func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("invalid number of admin users")
		}

		var admin admin
		err = json.Unmarshal(gr.Kvs[0].Value, &admin)
		if err != nil {
			return "", err
		}

		admin.LastLogin = time.Now().Format(time.RFC3339)
		admin.IP = ip

		b, _ := json.Marshal(admin)

		return string(b), nil

	})

}
