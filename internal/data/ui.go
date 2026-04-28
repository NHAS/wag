package data

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/crypto/argon2"
)

const (
	minPasswordLength = 14
	saltLength        = 8
	LocalUser         = "local"
	OidcUser          = "oidc"
)

// DTO

func (d *database) IncrementAdminAuthenticationAttempt(username string) error {
	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(admin config.Admin) (config.Admin, error) {

		l, err := d.GetLockout()
		if err != nil {
			return config.Admin{}, err
		}

		if admin.Attempts < l {
			admin.Attempts++
		}

		return admin, nil
	})

}

func (d *database) CreateLocalAdminUser(username, password string, changeOnFirstUse bool) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password is too short for administrative console (must be greater than %d characters)", minPasswordLength)
	}

	salt, err := utils.GenerateRandomHex(saltLength)
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

	newAdmin := config.Admin{
		AdminUserDTO: config.AdminUserDTO{
			Type:      LocalUser,
			Username:  username,
			DateAdded: time.Now().Format(time.RFC3339),
			Change:    changeOnFirstUse,
		},
		Hash: base64.RawStdEncoding.EncodeToString(append(hash, salt...)),
	}

	adminUserPath := InternalConfig.Admins().Key(username)

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(adminUserPath.Missing())
	tetcd.PutTx(then, adminUserPath, newAdmin)

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to add %q admin to database transaction failed: %w", username, err)
	}

	if !txn.Succeeded() {
		return fmt.Errorf("admin user %q already exists", username)
	}

	return nil
}

func (d *database) CreateOidcAdminUser(username, guid string) (config.AdminUserDTO, error) {

	dummy, err := utils.GenerateRandomHex(32)
	if err != nil {
		return config.AdminUserDTO{}, err
	}

	newAdmin := config.Admin{
		AdminUserDTO: config.AdminUserDTO{
			Type:      OidcUser,
			OidcGUID:  guid,
			Username:  username,
			DateAdded: time.Now().Format(time.RFC3339),
		},
		Hash: base64.RawStdEncoding.EncodeToString([]byte(dummy)), // we set a dummy unguessable password as the oidc admin hash, as that isnt its login mechanism
	}

	adminUserPath := InternalConfig.Admins().Key(username)
	oidcReferencePath := InternalConfig.References.Admins.OidcGuid().Key(guid)

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(adminUserPath.Missing(), oidcReferencePath.Missing())
	tetcd.PutTx(then, adminUserPath, newAdmin)
	tetcd.PutTx(then, oidcReferencePath, guid)

	if err := txn.Commit(); err != nil {
		return config.AdminUserDTO{}, fmt.Errorf("failed to add %q oidc admin to database transaction failed: %w", username, err)
	}

	if !txn.Succeeded() {
		return config.AdminUserDTO{}, fmt.Errorf("oidc admin user %q with GUID %q already exists", username, guid)
	}

	return newAdmin.AdminUserDTO, nil
}

func (d *database) CompareAdminKeys(username, password string) error {

	wasteTime := func() {
		// Null op to stop timing discovery attacks

		salt, _ := utils.GenerateRandomHex(saltLength)

		hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

		subtle.ConstantTimeCompare(hash, hash)
	}

	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(current config.Admin) (config.Admin, error) {

		lockout, err := d.GetLockout()
		if err != nil {
			return config.Admin{}, err
		}
		if current.Attempts >= lockout {
			wasteTime()
			return config.Admin{}, errors.New("account locked")
		}

		if current.Type == "" {
			current.Type = LocalUser
		}

		if current.Type == OidcUser {
			return config.Admin{}, errors.New("oidc users cannot sign in with compare admin keys")
		}

		rawHashSalt, err := base64.RawStdEncoding.DecodeString(current.Hash)
		if err != nil {
			return config.Admin{}, err
		}

		if len(rawHashSalt) < saltLength*2 {
			return config.Admin{}, errors.New("user has was not large enough to contain salt")
		}

		salt := rawHashSalt[len(rawHashSalt)-saltLength*2:]
		expectedHash := rawHashSalt[:len(rawHashSalt)-saltLength*2]

		thisHash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

		if subtle.ConstantTimeCompare(thisHash, expectedHash) != 1 {
			return config.Admin{}, errors.New("passwords did not match")
		}

		current.Attempts = 0

		return current, nil

	})
}

// Lock admin account and make them unable to login
func (d *database) SetAdminUserLock(username string) error {

	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(current config.Admin) (config.Admin, error) {
		var err error
		current.Attempts, err = d.GetLockout()
		if err != nil {
			return config.Admin{}, err
		}
		return current, nil
	})
}

// Unlock admin account
func (d *database) SetAdminUserUnlock(username string) error {

	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(current config.Admin) (config.Admin, error) {
		current.Attempts = 0
		return current, nil
	})
}

func (d *database) DeleteAdminUser(username string) error {

	result, err := InternalConfig.Admins().Key(username).Delete(context.Background(), d.etcd, clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	if len(result.PrevValues) > 0 {
		// if we actually delete something, and that something had a oidc guid, delete the reference

		guid := result.PrevValues[0].OidcGUID
		if len(guid) == 0 {
			return nil
		}

		_, err := InternalConfig.References.Admins.OidcGuid().Key(guid).Delete(context.Background(), d.etcd)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *database) GetAdminUser(username string) (a config.AdminUserDTO, err error) {

	response, err := InternalConfig.Admins().Key(username).Get(context.Background(), d.etcd)
	if err != nil {
		return a, err
	}

	return response.AdminUserDTO, nil
}

func (d *database) GetOidcAdminUser(subject string) (a config.AdminUserDTO, err error) {

	adminUsername, err := InternalConfig.References.Admins.OidcGuid().Key(subject).Get(context.Background(), d.etcd)
	if err != nil {
		return config.AdminUserDTO{}, fmt.Errorf("no username found for subject: %s: %w", subject, err)
	}

	response, err := InternalConfig.Admins().Key(adminUsername).Get(context.Background(), d.etcd)
	if err != nil {
		return config.AdminUserDTO{}, err
	}

	if response.Type != OidcUser {
		return config.AdminUserDTO{}, fmt.Errorf("user is not an OIDC user")
	}

	if len(response.OidcGUID) != 0 && response.OidcGUID != subject {
		return config.AdminUserDTO{}, fmt.Errorf("OIDC GUID does not match subject: %s", subject)
	}

	return response.AdminUserDTO, nil
}

func (d *database) GetAllAdminUsers() (adminUsers []config.AdminUserDTO, err error) {

	response, err := InternalConfig.Admins().Entries(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, admin := range response {
		adminUsers = append(adminUsers, admin.AdminUserDTO)
	}

	return
}

func (d *database) SetAdminPassword(username, password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password is too short for administrative console (must be greater than %d characters)", minPasswordLength)
	}

	salt, err := utils.GenerateRandomHex(saltLength)
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 10*1024, 4, 32)

	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(current config.Admin) (config.Admin, error) {
		if current.Type == current.OidcGUID {
			return config.Admin{}, errors.New("cannot set password for OIDC user")
		}

		current.Change = false
		current.Hash = base64.RawStdEncoding.EncodeToString(append(hash, salt...))
		return current, nil
	})

}

func (d *database) SetLastLoginInformation(username, ip string) error {

	return InternalConfig.Admins().Key(username).Update(context.Background(), d.etcd, false, func(current config.Admin) (config.Admin, error) {

		current.LastLogin = time.Now().Format(time.RFC3339)
		current.IP = ip

		return current, nil
	})
}
