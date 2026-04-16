package data

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/rs/zerolog/log"

	"go.etcd.io/etcd/client/v3/clientv3util"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (d *database) DeleteDeviceByTag(tag string) error {

	tagPath := InternalConfig.References.Devices.Tag().Key(tag)
	device, err := tagPath.Get(context.Background(), d.etcd)
	if err != nil {
		return fmt.Errorf("unable to delete device by tag: %q: %w", tagPath, err)
	}

	if device != "" {
		return d.deleteDevice(device)
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

func (d Device) ChallengeExists(etcd *clientv3.Client) error {
	_, err := Get[DeviceChallenge](etcd, DeviceChallengePrefix+d.Username+"-"+d.Address)
	return err
}

func (d Device) GetSensitiveChallenge(etcd *clientv3.Client) (string, error) {
	deviceWithChallenge, err := Get[Device](etcd, DevicesPrefix+d.Username+"-"+d.Address)

	return deviceWithChallenge.Challenge, err
}

func (d Device) SetChallenge(etcd *clientv3.Client) error {

	lease, err := clientv3.NewLease(etcd).Grant(context.Background(), 30)
	if err != nil {
		return err
	}

	var dc DeviceChallenge
	dc.Challenge = d.Challenge
	dc.Address = d.Address
	dc.Username = d.Username

	b, _ := json.Marshal(dc)

	_, err = etcd.Put(context.Background(), DeviceChallengePrefix+d.Username+"-"+d.Address, string(b), clientv3.WithLease(lease.ID))
	return err
}

func (d Device) String() string {

	authorised := "no"
	if !d.Authorised.Equal(time.Time{}) {
		authorised = d.Authorised.Format(time.DateTime)
	}

	return fmt.Sprintf("device[%s:%s:%s][attempts: %d, authorised: %s]", d.Username, d.Address, d.AssociatedNode, d.Attempts, authorised)
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
		return Device{}, err
	}

	if len(tag) > 100 {
		return Device{}, fmt.Errorf("tag was too large")
	}

	address := staticIp
	if _, err = netip.ParseAddr(staticIp); err != nil || staticIp == "" {
		address, err = d.getNextIP(config.Values.Wireguard.Address)
		if err != nil {
			return Device{}, err
		}
	}

	dev := Device{
		Address:      address,
		Publickey:    publickey,
		Username:     username,
		PresharedKey: preshared_key.String(),
		Tag:          tag,
	}

	b, _ := json.Marshal(dev)

	key := d.deviceKey(username, address)

	createOps := []clientv3.Op{
		clientv3.OpPut(key, string(b)),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", address), key),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", publickey), key),
	}

	cmp := []clientv3.Cmp{
		clientv3util.KeyMissing(key), clientv3util.KeyExists(UsersPrefix + username + "-"),
	}

	if len(tag) != 0 {
		createOps = append(createOps, clientv3.OpPut(d.getTagPath(tag), key))
		cmp = append(cmp, clientv3util.KeyMissing(d.getTagPath(tag)))

	}

	response, err := d.etcd.Txn(context.Background()).If(cmp...).Then(createOps...).Commit()
	if err != nil {
		return Device{}, err
	}

	if !response.Succeeded {

		if len(tag) > 0 {
			return Device{}, fmt.Errorf("device with %q address or tag %q already exists", address, tag)

		}

		return Device{}, fmt.Errorf("device with %q address already exists", address)
	}

	return dev, err
}

func (d *database) deleteDevice(key string) error {
	resp, err := d.etcd.Delete(context.Background(), key, clientv3.WithPrevKV())
	if err != nil {
		return fmt.Errorf("could not delete device by direct key: %q: %w", key, err)
	}

	if len(resp.PrevKvs) != 0 {

		var dev Device
		err := json.Unmarshal(resp.PrevKvs[0].Value, &dev)
		if err != nil {
			return fmt.Errorf("could not parse device: %w", err)
		}

		_, err = d.etcd.Txn(context.Background()).Then(d.deleteDeviceOps(dev)...).Commit()
		return err

	}

	return nil

}

// DeleteDevice removes a single device from etcd
// id can be a public key, or ip address
func (d *database) DeleteDevice(id string) error {

	refKey := deviceRef + id

	realKey, err := d.etcd.Get(context.Background(), refKey)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("no reference found")
	}

	deviceEntry, err := d.etcd.Get(context.Background(), string(realKey.Kvs[0].Value))
	if err != nil {
		return fmt.Errorf("unable to get real device entry from reference: %s", err)
	}

	var dev Device
	err = json.Unmarshal(deviceEntry.Kvs[0].Value, &dev)
	if err != nil {
		return err
	}

	_, err = d.etcd.Txn(context.Background()).Then(d.deleteDeviceOps(dev)...).Commit()

	return err
}

// Generate the operations to delete a device
func (d *database) deleteDeviceOps(dev Device) []clientv3.Op {

	key := d.deviceKey(dev.Username, dev.Address)
	ipRef := deviceRef + dev.Address
	publicKeyRef := deviceRef + dev.Publickey

	sessionRef := DeviceSessionPrefix + dev.Address

	challengeKey := DeviceChallengePrefix + dev.Username + "-" + dev.Address

	return []clientv3.Op{
		clientv3.OpPut(dhcpAbandonedPrefix+dev.Address, fmt.Sprintf("%q", dev.Address)),

		clientv3.OpDelete(key),

		clientv3.OpDelete(ipRef),
		clientv3.OpDelete(publicKeyRef),

		clientv3.OpDelete(sessionRef),
		clientv3.OpDelete(challengeKey),

		clientv3.OpDelete(d.getTagPath(dev.Tag)),
	}
}

func (d *database) DeleteDevices(username string) error {

	deleted, err := d.etcd.Delete(context.Background(), fmt.Sprintf("%s%s-", DevicesPrefix, username), clientv3.WithPrefix(), clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	var ops []clientv3.Op
	for _, reference := range deleted.PrevKvs {

		var dev Device
		err := json.Unmarshal(reference.Value, &dev)
		if err != nil {
			log.Error().Err(err).Str("username", username).Msg("Failed to delete device")
			continue
		}

		ops = append(ops, d.deleteDeviceOps(dev)...)

	}

	_, err = d.etcd.Txn(context.Background()).Then(ops...).Commit()
	return err
}

func (d *database) UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error {

	beforeUpdate, err := d.GetDeviceByAddress(address)
	if err != nil {
		return err
	}

	err = d.doSafeUpdate(context.Background(), d.deviceKey(username, address), false, func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		device.Publickey = publicKey.String()

		b, _ := json.Marshal(device)

		return string(b), err
	})

	if err != nil {
		return err
	}

	_, err = d.etcd.Delete(context.Background(), deviceRef+beforeUpdate.Publickey)

	return err
}

func (d *database) GetDeviceByAddress(address string) (device Device, err error) {

	realKey, err := d.etcd.Get(context.Background(), deviceRef+address)
	if err != nil {
		return Device{}, err
	}

	if len(realKey.Kvs) == 0 {
		return Device{}, errors.New("not device found for address: " + address)
	}

	if len(realKey.Kvs) != 1 {
		return Device{}, errors.New("incorrect number of keys for device reference")
	}

	response, err := d.etcd.Get(context.Background(), string(realKey.Kvs[0].Value))
	if err != nil {
		return Device{}, err
	}

	if len(response.Kvs) == 0 {
		return Device{}, errors.New("device was not found")
	}

	if len(response.Kvs) > 1 {
		return Device{}, errors.New("user device has multiple keys")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &device)

	return
}

func (d *database) GetDevicesByUser(username string) (devices []Device, err error) {

	response, err := d.etcd.Get(context.Background(), fmt.Sprintf(DevicesPrefix+"%s-", username), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var device Device
		err := json.Unmarshal(res.Value, &device)
		if err != nil {
			return nil, err
		}

		devices = append(devices, device)
	}

	return
}
