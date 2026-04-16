package data

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"go.etcd.io/etcd/client/v3/clientv3util"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (d *database) DeleteDeviceByTag(tag string) error {

	tagPath := InternalConfig.References.Devices.Tag().Key(tag)
	ref, err := tagPath.Get(context.Background(), d.etcd)
	if err != nil {
		return fmt.Errorf("unable to delete device by tag: %q: %w", tagPath, err)
	}

	if !ref.Empty() {
		return d.DeleteDevice(ref.Address)
	}

	return nil
}

func (d *database) ValidateChallenge(username, address, challenge string) error {

	dc, err := InternalConfig.Devices.Challenges().Key(username).Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return err
	}

	if dc.Address != address || dc.Username != username {
		return errors.New("invalid contents of challenge")
	}

	if subtle.ConstantTimeCompare([]byte(dc.Challenge), []byte(challenge)) != 0 {
		return errors.New("device challenge did not match stored challenge")
	}

	device, err := d.GetDevice(username, address)
	if err != nil {
		return errors.New("unable to find device for user (challenge)")
	}

	if subtle.ConstantTimeCompare([]byte(dc.Challenge), []byte(device.Challenge)) != 0 {
		return errors.New("device challenge did not match device stored challenge")
	}

	return nil
}

func (d *database) ChallengeExists(device config.Device) error {

	_, err := InternalConfig.Devices.Challenges().Key(device.Username).Key(device.Address).Get(context.Background(), d.etcd)
	return err
}

func (d *database) GetSensitiveChallenge(device config.Device) (string, error) {
	deviceWithChallenge, err := InternalConfig.Devices.Challenges().Key(device.Username).Key(device.Address).Get(context.Background(), d.etcd)
	if err != nil {
		return "", err
	}

	return deviceWithChallenge.Challenge, nil
}

func (d *database) SetChallenge(device config.Device) error {
	lease, err := clientv3.NewLease(d.etcd).Grant(context.Background(), 30)
	if err != nil {
		return err
	}

	dc := config.DeviceChallenge{
		Challenge: device.Challenge,
		Address:   device.Address,
		Username:  device.Username,
	}

	return InternalConfig.Devices.Challenges().
		Key(device.Username).
		Key(device.Address).
		Put(context.Background(), d.etcd, dc, clientv3.WithLease(lease.ID))
}

// UpdateDeviceConnectionDetails updates the endpoint we are receiving packets from and the associated cluster node
// I.e if data is coming in to node 3, all other nodes know that the session is only valid while connecting to node 3
// this stops a race condition where an attacker uses a wireguard profile, but gets load balanced to another node member
func (d *database) UpdateDeviceConnectionDetails(address string, endpoint *net.UDPAddr) error {

	realKey, err := InternalConfig.References.Devices.Address().Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return err
	}

	return InternalConfig.Devices.Machines().
		Key(realKey.Username).
		Key(realKey.Address).
		Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {

			device.Endpoint = endpoint
			device.AssociatedNode = d.GetCurrentNodeID()
			device.Challenge, err = utils.GenerateRandomHex(32)
			if err != nil {
				return device, fmt.Errorf("failed to generate random challenge on device authorisation: %s", err)
			}

			return device, nil
		})
}

func (d *database) GetDevice(username, id string) (device config.Device, err error) {

	return InternalConfig.Devices.Machines().Key(username).Key(id).Get(context.Background(), d.etcd)
}

func (d *database) HasDeviceAuthorised(current, previous config.Device) bool {
	lockout, err := d.GetLockout()
	if err != nil {
		return false
	}

	return current.Authorised != previous.Authorised &&
		!current.Authorised.IsZero() &&
		current.Attempts <= lockout &&
		(current.AssociatedNode == previous.AssociatedNode || previous.AssociatedNode == 0)
}

// Set device as authorized and clear authentication attempts
func (d *database) AuthoriseDevice(username, address string) error {
	err := InternalConfig.Devices.Machines().Key(username).Key(address).Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {
		u, err := d.GetUserData(device.Username)
		if err != nil {
			// We may want to make this lock the device if the user is not found. At the moment settle with doing nothing
			return device, err
		}

		if u.Locked {
			return device, errors.New("account is locked")
		}

		device.AssociatedNode = d.GetCurrentNodeID()
		device.Authorised = time.Now()
		device.Attempts = 0
		device.Challenge, err = utils.GenerateRandomHex(32)
		if err != nil {
			return device, fmt.Errorf("failed to generate random challenge on device authorisation: %s", err)
		}

		return device, nil
	})
	if err != nil {
		return fmt.Errorf("failed to update device authorisation state: %s", err)
	}

	return d.markDeviceSessionStarted(address, username)
}

func (d *database) GetAllSessions() (sessions []config.DeviceSession, err error) {

	order, data, err := InternalConfig.Devices.Sessions().List(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	// otherwise json returns null
	sessions = []config.DeviceSession{}
	for _, session := range order {
		sessions = append(sessions, data[session])
	}

	return sessions, nil
}

func (d *database) markDeviceSessionStarted(address, username string) error {

	ops := []clientv3.OpOption{}

	maxSession, err := d.GetSessionLifetimeMinutes()
	if err != nil {
		return err
	}

	// sessions are permanently active unless logged out if max Session is disabled
	if maxSession > 0 {
		// turn maxSession into seconds for etcd
		lease, err := clientv3.NewLease(d.etcd).Grant(context.Background(), int64(maxSession)*60)
		if err != nil {
			return err
		}

		ops = append(ops, clientv3.WithLease(lease.ID))
	}

	ds := config.DeviceSession{
		Address:  address,
		Username: username,
		Started:  time.Now(),
	}

	return InternalConfig.Devices.Sessions().Key(address).Put(context.Background(), d.etcd, ds, ops...)
}

func (d *database) MarkDeviceSessionEnded(address string) error {

	_, err := InternalConfig.Devices.Sessions().Key(address).Delete(context.Background(), d.etcd)
	return err
}

func (d *database) DeauthenticateDevice(address string) error {

	ref, err := InternalConfig.References.Devices.Address().Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return err
	}

	if ref.Empty() {
		return errors.New("device was not found")
	}

	err = InternalConfig.Devices.Machines().
		Key(ref.Username).
		Key(ref.Address).
		Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {
			device.Authorised = time.Time{}
			return device, err
		})
	if err != nil {
		return err
	}

	return d.MarkDeviceSessionEnded(address)
}

func (d *database) SetDeviceAuthenticationAttempts(username, address string, attempts int) error {
	return InternalConfig.Devices.Machines().
		Key(username).
		Key(address).
		Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {
			device.Attempts = attempts
			return device, nil
		})
}

func (d *database) GetAllDevices() (devices []config.Device, err error) {
	return InternalConfig.Devices.Machines().Entries(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
}

func (d *database) AddDevice(username, publickey, staticIp, tag string) (config.Device, error) {

	preshared_key, err := wgtypes.GenerateKey()
	if err != nil {
		return config.Device{}, err
	}

	if len(tag) > 100 {
		return config.Device{}, fmt.Errorf("tag was too large")
	}

	address := staticIp
	if _, err = netip.ParseAddr(staticIp); err != nil || staticIp == "" {
		address, err = d.getNextIP(config.Values.Wireguard.Address)
		if err != nil {
			return config.Device{}, err
		}
	}

	dev := config.Device{
		Address:      address,
		Publickey:    publickey,
		Username:     username,
		PresharedKey: preshared_key.String(),
		Tag:          tag,
	}

	ref := config.DeviceRef{
		Address:  address,
		Username: username,
	}

	devicePath := InternalConfig.Devices.Machines().Key(username).Key(address)
	tagPath := InternalConfig.References.Devices.Tag().Key(tag)

	cmp := []clientv3.Cmp{
		clientv3util.KeyMissing(devicePath.Key()), clientv3util.KeyExists(InternalConfig.Users().Key(username).Key()),
	}

	if len(tag) != 0 {
		cmp = append(cmp, clientv3util.KeyMissing(tagPath.Key()))
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(cmp...)

	err = tetcd.PutTx(then, devicePath, dev)
	if err != nil {
		return config.Device{}, err
	}

	err = tetcd.PutTx(then, InternalConfig.References.Devices.Address().Key(address), ref)
	if err != nil {
		return config.Device{}, err
	}

	err = tetcd.PutTx(then, InternalConfig.References.Devices.PublicKey().Key(publickey), ref)
	if err != nil {
		return config.Device{}, err
	}

	if len(tag) != 0 {
		err = tetcd.PutTx(then, tagPath, ref)
		if err != nil {
			return config.Device{}, err
		}
	}

	if err := txn.Commit(); err != nil {
		return config.Device{}, err
	}

	if !txn.Succeeded() {

		if len(tag) > 0 {
			return config.Device{}, fmt.Errorf("device with %q address or tag %q already exists", address, tag)
		}

		return config.Device{}, fmt.Errorf("device with %q address already exists", address)
	}

	return dev, err
}

// DeleteDevice removes a single device from etcd by ip address
func (d *database) DeleteDevice(address string) error {

	ref, err := InternalConfig.References.Devices.Address().Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return err
	}

	if ref.Empty() {
		return errors.New("no address reference found")
	}

	device, err := InternalConfig.Devices.Machines().Key(ref.Username).Key(ref.Address).Get(context.Background(), d.etcd)
	if err != nil {
		return fmt.Errorf("unable to get real device entry from reference: %s", err)
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	d.applyDeleteDeviceOps(then, device)

	return txn.Commit()
}

// Generate the operations to delete a device
func (d *database) applyDeleteDeviceOps(txn *tetcd.TxnConditional, dev config.Device) {

	// mark that the ip address is no longer in use
	tetcd.PutTx(txn, InternalConfig.Devices.DHCP.Abandoned().Key(dev.Address), dev.Address)

	// Delete the device itself
	tetcd.DeleteTx(txn, InternalConfig.Devices.Machines().Key(dev.Username).Key(dev.Address))

	// clean up the 3 reference types
	tetcd.DeleteTx(txn, InternalConfig.References.Devices.Address().Key(dev.Address))
	tetcd.DeleteTx(txn, InternalConfig.References.Devices.PublicKey().Key(dev.Publickey))
	tetcd.DeleteTx(txn, InternalConfig.References.Devices.Tag().Key(dev.Tag))

	// clean up challenges
	tetcd.DeleteTx(txn, InternalConfig.Devices.Challenges().Key(dev.Username).Key(dev.Address))

	// clean up any existing sessions
	tetcd.DeleteTx(txn, InternalConfig.Devices.Sessions().Key(dev.Address))

}

func (d *database) DeleteDevices(username string) error {

	result, err := InternalConfig.Devices.Machines().Key(username).DeleteAll(context.Background(), d.etcd, clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	for _, device := range result.PrevValues {
		d.applyDeleteDeviceOps(then, device)
	}

	return txn.Commit()
}

func (d *database) UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error {

	beforeUpdate := publicKey.String()

	err := InternalConfig.Devices.Machines().Key(username).Key(address).Update(context.Background(), d.etcd, false, func(device config.Device) (config.Device, error) {
		device.Publickey = publicKey.String()
		return device, nil
	})

	if err != nil {
		return err
	}

	return InternalConfig.References.Devices.PublicKey().Delete(context.Background(), d.etcd, beforeUpdate)
}

func (d *database) GetDeviceByAddress(address string) (config.Device, error) {

	ref, err := InternalConfig.References.Devices.Address().Key(address).Get(context.Background(), d.etcd)
	if err != nil {
		return config.Device{}, err
	}

	if ref.Empty() {
		return config.Device{}, errors.New("not device found for address: " + address)
	}

	device, err := InternalConfig.Devices.Machines().Key(ref.Username).Key(ref.Address).Get(context.Background(), d.etcd)
	if err != nil {
		return config.Device{}, err
	}

	return device, nil
}

func (d *database) GetDevicesByUser(username string) (devices []config.Device, err error) {
	return InternalConfig.Devices.Machines().Key(username).Entries(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
}
