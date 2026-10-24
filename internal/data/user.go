package data

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
)

// IncrementAuthenticationAttempt Make sure that the attempts is always incremented first to stop race condition attacks
func (d *Database) IncrementAuthenticationAttempt(username, device string) error {
	return InternalConfig.Devices.Machines().
		Key(username).
		Key(device).
		Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {

			l, err := d.GetLockout()
			if err != nil {
				return config.Device{}, err
			}

			if device.Attempts <= l {
				device.Attempts++
			}

			return device, nil
		})
}

func (d *Database) GetAuthenticationDetails(username, address string) (mfa, mfaType string, attempts int, locked bool, err error) {

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	userH := then.Get(InternalConfig.Users().Key(username))
	deviceH := then.Get(InternalConfig.Devices.Machines().Key(username).Key(address))

	if err = txn.Commit(); err != nil {
		return
	}

	user, err := userH.Value()
	if err != nil {
		err = fmt.Errorf("failed to fetch user object: %w", err)
		return
	}

	mfa = user.Mfa
	mfaType = user.MfaType
	locked = user.Locked

	device, err := deviceH.Value()
	if err != nil {
		err = fmt.Errorf("failed to fetch device object: %w", err)
		return
	}

	attempts = device.Attempts

	return
}

// Disable authentication for user
func (d *Database) SetUserLock(username string) error {
	err := InternalConfig.Users().Key(username).Update(context.Background(), d.etcd, false, func(user config.UserModel) (config.UserModel, error) {
		user.Locked = true
		return user, nil

	})
	if err != nil {
		return fmt.Errorf("Unable to lock account: %w", err)
	}

	return nil
}

func (d *Database) SetUserUnlock(username string) error {
	err := InternalConfig.Users().Key(username).Update(context.Background(), d.etcd, false, func(user config.UserModel) (config.UserModel, error) {
		user.Locked = false
		return user, nil

	})
	if err != nil {
		return fmt.Errorf("Unable to unlock account: %w", err)
	}

	return nil
}

// Has the user recorded their MFA details. Always read the latest value from the DB
func (d *Database) IsEnforcingMFA(username string) bool {

	user, err := InternalConfig.Users().Key(username).Get(context.Background(), d.etcd)
	if err != nil {
		// Fail closed rather than allowing a user to re-register their mfa on db error
		return true
	}

	return user.Enforcing
}

// Stop displaying MFA secrets for user
func (d *Database) SetEnforceMFAOn(username string) error {

	return InternalConfig.Users().Key(username).Update(context.Background(), d.etcd, false, func(user config.UserModel) (config.UserModel, error) {
		user.Enforcing = true
		return user, nil
	})
}

func (d *Database) SetEnforceMFAOff(username string) error {

	return InternalConfig.Users().Key(username).Update(context.Background(), d.etcd, false, func(user config.UserModel) (config.UserModel, error) {
		user.Enforcing = false
		return user, nil
	})
}

func (d *Database) GetMFASecret(username string) (string, error) {

	user, err := InternalConfig.Users().Key(username).Get(context.Background(), d.etcd)
	if err != nil {
		return "", fmt.Errorf("failed to get user mfa secret: %w", err)
	}

	// The webauthn "secret" needs to be used, but isnt returned to the client
	if user.Enforcing && user.MfaType != "webauthn" {
		return "", errors.New("MFA is set to enforcing, will not return details (unless webauthn)")
	}

	return user.Mfa, nil
}

func (d *Database) GetMFAType(username string) (string, error) {

	user, err := InternalConfig.Users().Key(username).Get(context.Background(), d.etcd)
	if err != nil {
		return "", fmt.Errorf("failed to get user mfa secret: %w", err)
	}

	return user.MfaType, nil
}

func (d *Database) DeleteUser(username string) error {

	var errs []error

	_, err := InternalConfig.Users().Key(username).Delete(context.Background(), d.etcd)
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

func (d *Database) GetUserData(username string) (u config.UserModel, err error) {
	return InternalConfig.Users().Key(username).Get(context.Background(), d.etcd)
}

func (d *Database) GetUserDataFromAddress(address string) (u config.UserModel, err error) {

	ref, err := InternalConfig.References.Devices.Address().Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return
	}

	if ref.Empty() {
		return u, fmt.Errorf("reference was empty when looking up user from address")
	}

	return d.GetUserData(ref.Username)
}

func (d *Database) SetUserMfa(username, value, mfaType string) error {

	return InternalConfig.Users().
		Key(username).
		Update(context.Background(), d.etcd, false, func(user config.UserModel) (config.UserModel, error) {
			user.Mfa = value
			user.MfaType = mfaType
			return user, nil
		})
}

func (d *Database) CreateUserDataAccount(username string) (config.UserModel, error) {

	if strings.Contains(username, "-") {
		return config.UserModel{}, errors.New("usernames may not contain '-' ")
	}

	if len(username) == 0 {
		return config.UserModel{}, errors.New("username is too short")
	}

	if len(username) > 128 {
		return config.UserModel{}, errors.New("username is too long")
	}

	newUser := config.UserModel{
		Username: username,
		Mfa:      string(types.Unset),
		MfaType:  string(types.Unset),
	}

	err := InternalConfig.Users().Key(username).Put(context.Background(), d.etcd, newUser)
	if err != nil {
		return config.UserModel{}, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, err
}

func (d *Database) GetAllUsers() (users []config.UserModel, err error) {
	return InternalConfig.Users().Entries(context.Background(), d.etcd)
}
