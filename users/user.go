package users

import (
	"errors"
	"fmt"
	"net"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
	"github.com/NHAS/wag/webserver/authenticators"
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

	devices, err := u.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range devices {
		err := router.Deauthenticate(device.Address)
		if err != nil {
			return err
		}
	}

	err = data.SetUserMfa(u.Username, "", authenticators.UnsetMFA)
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

	device, err := data.GetDeviceByAddress(address)
	if err != nil {
		return err
	}

	err = router.ReplacePeer(device, key)
	if err != nil {
		return err
	}

	return data.UpdateDevicePublicKey(u.Username, address, key)
}

func (u *user) AddDevice(publickey wgtypes.Key) (device data.Device, err error) {

	address, err := router.AddPeer(publickey, u.Username)
	if err != nil {
		return data.Device{}, err
	}

	return data.AddDevice(u.Username, address, publickey.String())
}

func (u *user) DeleteDevice(address string) (err error) {

	device, err := data.GetDevice(u.Username, address)
	if err != nil {
		return err
	}

	var errStr string
	err = router.RemovePeer(device.Publickey, address)
	if err != nil {
		errStr += err.Error()
	}

	err = data.DeleteDevice(u.Username, address)
	if err != nil {
		errStr += "" + err.Error()
	}

	if len(errStr) == 0 {
		return nil
	}

	return errors.New(errStr)
}

func (u *user) GetDevice(id string) (device data.Device, err error) {
	return data.GetDevice(u.Username, id)
}

func (u *user) GetDevices() (device []data.Device, err error) {
	return data.GetDevicesByUser(u.Username)
}

func (u *user) Lock() error {
	u.Locked = true

	devices, err := u.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range devices {
		err := router.Deauthenticate(device.Address)
		if err != nil {
			return err
		}
	}
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

	devices, err := u.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range devices {
		err := router.RemovePeer(device.Publickey, device.Address)
		if err != nil {
			return err
		}
	}

	err = router.RemoveUser(u.Username)
	if err != nil {
		return err
	}

	return data.DeleteUser(u.Username)
}

func (u *user) Authenticate(device, mfaType string, authenticator authenticators.AuthenticatorFunc) error {

	// Make sure that the attempts is always incremented first to stop race condition attacks
	err := data.IncrementAuthenticationAttempt(u.Username, device)
	if err != nil {
		return err
	}

	mfa, userMfaType, attempts, locked, err := data.GetAuthenticationDetails(u.Username, device)
	if err != nil {
		return err
	}

	if attempts > config.Values().Lockout {
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

	err = u.ResetDeviceAuthAttempts(device)
	if err != nil {
		return fmt.Errorf("%s %s unable to reset number of mfa attempts: %s", u.Username, device, err)
	}

	err = router.SetAuthorized(device, u.Username)
	if err != nil {
		return fmt.Errorf("%s %s unable to add mfa routes: %s", u.Username, device, err)
	}

	return nil
}

func (u *user) MFA() (string, error) {
	url, err := data.GetMFASecret(u.Username)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (u *user) GetMFAType() string {
	mType, err := data.GetMFAType(u.Username)

	if err != nil {
		mType = authenticators.UnsetMFA
	}

	return mType
}

func CreateUser(username string) (user, error) {
	ud, err := data.CreateUserDataAccount(username)
	if err != nil {
		return user{}, err
	}

	err = router.AddUser(username, config.GetEffectiveAcl(username))
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
	ud, err := data.GetUserDataFromAddress(address.To4().String())
	if err != nil {
		return user{}, err
	}

	return user{ud.Username, ud.Locked, ud.Enforcing}, nil
}
