package users

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type user struct {
	Username  string
	Locked    bool
	Enforcing bool

	db interfaces.Database `json:"-"`
}

func (u *user) ResetDeviceAuthAttempts(address string) error {
	return u.db.SetDeviceAuthenticationAttempts(u.Username, address, 0)
}

func (u *user) ResetMfa() error {

	err := u.db.SetUserMfa(u.Username, u.Username, string(types.Unset))
	if err != nil {
		return err
	}

	return u.UnenforceMFA()
}

func (u *user) SetDeviceAuthAttempts(address string, number int) error {
	return u.db.SetDeviceAuthenticationAttempts(u.Username, address, number)
}

func (u *user) SetDevicePublicKey(publickey, address string) (err error) {
	key, err := wgtypes.ParseKey(publickey)
	if err != nil {
		return err
	}

	return u.db.UpdateDevicePublicKey(u.Username, address, key)
}

func (u *user) GetDevicePresharedKey(address string) (presharedKey string, err error) {
	device, err := u.db.GetDeviceByAddress(address)
	if err != nil {
		return "", err
	}

	if device.PresharedKey == "unset" {
		device.PresharedKey = ""
	}

	return device.PresharedKey, nil
}

func (u *user) AddDevice(publickey wgtypes.Key, staticIp string) (device data.Device, err error) {

	return u.db.AddDevice(u.Username, publickey.String(), staticIp)
}

func (u *user) DeleteDevice(address string) (err error) {

	return u.db.DeleteDevice(u.Username, address)
}

func (u *user) GetDevice(id string) (device data.Device, err error) {
	return u.db.GetDevice(u.Username, id)
}

func (u *user) GetDevices() (device []data.Device, err error) {
	return u.db.GetDevicesByUser(u.Username)
}

func (u *user) Lock() error {
	u.Locked = true

	return u.db.SetUserLock(u.Username)
}

func (u *user) Unlock() error {
	u.Locked = false
	return u.db.SetUserUnlock(u.Username)
}

func (u *user) EnforceMFA() error {
	return u.db.SetEnforceMFAOn(u.Username)
}

func (u *user) UnenforceMFA() error {
	return u.db.SetEnforceMFAOff(u.Username)
}

func (u *user) IsEnforcingMFA() bool {
	return u.db.IsEnforcingMFA(u.Username)
}

func (u *user) Delete() error {
	return u.db.DeleteUser(u.Username)
}

func (u *user) Authenticate(device, mfaType string, authenticator types.AuthenticatorFunc) error {

	// Make sure that the attempts is always incremented first to stop race condition attacks
	err := u.db.IncrementAuthenticationAttempt(u.Username, device)
	if err != nil {
		return fmt.Errorf("failed to pre-emptively increment authentication attempt counter: %s", err)
	}

	mfa, userMfaType, attempts, locked, err := u.db.GetAuthenticationDetails(u.Username, device)
	if err != nil {
		return fmt.Errorf("failed to get authenticator details: %s", err)
	}

	lockout, err := u.db.GetLockout()
	if err != nil {
		return errors.New("could not get lockout value")
	}

	if attempts >= lockout {
		return errors.New("device is locked")
	}

	if locked {
		return errors.New("account is locked")
	}

	if userMfaType != mfaType {
		return errors.New("authenticator " + mfaType + " used for user with " + userMfaType)
	}

	if err := authenticator(mfa, u.Username); err != nil {
		return err
	}

	// Device has now successfully authenticated
	if !u.IsEnforcingMFA() {
		err := u.EnforceMFA()
		if err != nil {
			return fmt.Errorf("%s %s failed to set MFA to enforcing: %s", u.Username, device, err)
		}
	}

	err = u.db.AuthoriseDevice(u.Username, device)
	if err != nil {
		return fmt.Errorf("%s %s unable to reset number of mfa attempts: %s", u.Username, device, err)
	}

	return nil
}

func (u *user) Deauthenticate(device string) error {
	return u.db.DeauthenticateDevice(device)
}

func (u *user) MFA() (string, error) {
	url, err := u.db.GetMFASecret(u.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get MFA details: %s", err)
	}

	return url, nil
}

func (u *user) GetMFAType() string {
	mType, err := u.db.GetMFAType(u.Username)

	if err != nil {
		mType = string(types.Unset)
	}

	return mType
}

func CreateUser(db interfaces.Database, username string) (user, error) {
	ud, err := db.CreateUserDataAccount(username)
	if err != nil {
		return user{}, err
	}

	return user{
		db:        db,
		Username:  ud.Username,
		Locked:    ud.Locked,
		Enforcing: ud.Enforcing,
	}, nil
}

func GetUser(db interfaces.Database, username string) (user, error) {

	ud, err := db.GetUserData(username)
	if err != nil {
		return user{}, err
	}

	return user{
		db:        db,
		Username:  ud.Username,
		Locked:    ud.Locked,
		Enforcing: ud.Enforcing,
	}, nil
}

func GetUserFromAddress(db interfaces.Database, address net.IP) (user, error) {
	if address == nil {
		return user{}, errors.New("address was nil")
	}

	ud, err := db.GetUserDataFromAddress(address.String())
	if err != nil {
		return user{}, err
	}

	return user{
		db:        db,
		Username:  ud.Username,
		Locked:    ud.Locked,
		Enforcing: ud.Enforcing,
	}, nil
}

type contextKey string

// Define context key for user
const UserContextKey contextKey = "user"

// crash out intentionally if the user key is not in the context
func GetUserFromContext(ctx context.Context) *user {
	return ctx.Value(UserContextKey).(*user)
}
