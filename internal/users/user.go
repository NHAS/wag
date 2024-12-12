package users

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type user struct {
	Username  string
	Locked    bool
	Enforcing bool
}

func (u *user) ResetDeviceAuthAttempts(address string) error {
	return data.SetDeviceAuthenticationAttempts(u.Username, address, 0)
}

func (u *user) ResetMfa() error {

	err := data.SetUserMfa(u.Username, u.Username, string(types.Unset))
	if err != nil {
		return err
	}

	return u.UnenforceMFA()
}

func (u *user) SetDeviceAuthAttempts(address string, number int) error {
	return data.SetDeviceAuthenticationAttempts(u.Username, address, number)
}

func (u *user) SetDevicePublicKey(publickey, address string) (err error) {
	key, err := wgtypes.ParseKey(publickey)
	if err != nil {
		return err
	}

	return data.UpdateDevicePublicKey(u.Username, address, key)
}

func (u *user) GetDevicePresharedKey(address string) (presharedKey string, err error) {
	device, err := data.GetDeviceByAddress(address)
	if err != nil {
		return "", err
	}

	if device.PresharedKey == "unset" {
		device.PresharedKey = ""
	}

	return device.PresharedKey, nil
}

func (u *user) AddDevice(publickey wgtypes.Key) (device data.Device, err error) {

	return data.AddDevice(u.Username, publickey.String())
}

func (u *user) DeleteDevice(address string) (err error) {

	return data.DeleteDevice(u.Username, address)
}

func (u *user) GetDevice(id string) (device data.Device, err error) {
	return data.GetDevice(u.Username, id)
}

func (u *user) GetDevices() (device []data.Device, err error) {
	return data.GetDevicesByUser(u.Username)
}

func (u *user) Lock() error {
	u.Locked = true

	return data.SetUserLock(u.Username)
}

func (u *user) Unlock() error {
	u.Locked = false
	return data.SetUserUnlock(u.Username)
}

func (u *user) EnforceMFA() error {
	return data.SetEnforceMFAOn(u.Username)
}

func (u *user) UnenforceMFA() error {
	return data.SetEnforceMFAOff(u.Username)
}

func (u *user) IsEnforcingMFA() bool {
	return data.IsEnforcingMFA(u.Username)
}

func (u *user) Delete() error {
	return data.DeleteUser(u.Username)
}

func (u *user) Authenticate(device, mfaType string, authenticator types.AuthenticatorFunc) (string, error) {

	// Make sure that the attempts is always incremented first to stop race condition attacks
	err := data.IncrementAuthenticationAttempt(u.Username, device)
	if err != nil {
		return "", fmt.Errorf("failed to pre-emptively increment authentication attempt counter: %s", err)
	}

	mfa, userMfaType, attempts, locked, err := data.GetAuthenticationDetails(u.Username, device)
	if err != nil {
		return "", fmt.Errorf("failed to get authenticator details: %s", err)
	}

	lockout, err := data.GetLockout()
	if err != nil {
		return "", errors.New("could not get lockout value")
	}

	if attempts >= lockout {
		return "", errors.New("device is locked")
	}

	if locked {
		return "", errors.New("account is locked")
	}

	if userMfaType != mfaType {
		return "", errors.New("authenticator " + mfaType + " used for user with " + userMfaType)
	}

	if err := authenticator(mfa, u.Username); err != nil {
		return "", err
	}

	// Device has now successfully authenticated
	if !u.IsEnforcingMFA() {
		err := u.EnforceMFA()
		if err != nil {
			return "", fmt.Errorf("%s %s failed to set MFA to enforcing: %s", u.Username, device, err)
		}
	}

	challenge, err := data.AuthoriseDevice(u.Username, device)
	if err != nil {
		return "", fmt.Errorf("%s %s unable to reset number of mfa attempts: %s", u.Username, device, err)
	}

	return challenge, nil
}

func (u *user) Deauthenticate(device string) error {
	return data.DeauthenticateDevice(device)
}

func (u *user) MFA() (string, error) {
	url, err := data.GetMFASecret(u.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get MFA details: %s", err)
	}

	return url, nil
}

func (u *user) GetMFAType() string {
	mType, err := data.GetMFAType(u.Username)

	if err != nil {
		mType = string(types.Unset)
	}

	return mType
}

func CreateUser(username string) (user, error) {
	ud, err := data.CreateUserDataAccount(username)
	if err != nil {
		return user{}, err
	}
	return user{ud.Username, ud.Locked, ud.Enforcing}, nil
}

func GetUser(username string) (user, error) {

	ud, err := data.GetUserData(username)
	if err != nil {
		return user{}, err
	}

	return user{ud.Username, ud.Locked, ud.Enforcing}, nil
}

func GetUserFromAddress(address net.IP) (user, error) {
	if address == nil {
		return user{}, errors.New("address was nil")
	}
	ud, err := data.GetUserDataFromAddress(address.String())
	if err != nil {
		return user{}, err
	}

	return user{ud.Username, ud.Locked, ud.Enforcing}, nil
}

type contextKey string

// Define context key for user
const UserContextKey contextKey = "user"

// crash out intentionally if the user key is not in the context
func GetUserFromContext(ctx context.Context) user {
	return ctx.Value(UserContextKey).(user)
}
