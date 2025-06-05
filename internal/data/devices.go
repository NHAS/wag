package data

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/client/v3/clientv3util"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Device struct {
	Version        int
	Address        string
	Publickey      string
	Username       string
	PresharedKey   string `sensitive:"yes"`
	Endpoint       *net.UDPAddr
	Attempts       int
	Authorised     time.Time
	Challenge      string `sensitive:"yes"`
	AssociatedNode types.ID
}

type DeviceChallenge struct {
	Address   string
	Username  string
	Challenge string `sensitive:"yes"`
}

func ValidateChallenge(username, address, challenge string) error {
	dc, err := get[DeviceChallenge](DeviceChallengePrefix + username + "-" + address)
	if err != nil {
		return err
	}

	if dc.Address != address || dc.Username != username {
		return errors.New("invalid contents of challenge")
	}

	if subtle.ConstantTimeCompare([]byte(dc.Challenge), []byte(challenge)) != 0 {
		return errors.New("device challenge did not match stored challenge")
	}

	device, err := GetDevice(username, address)
	if err != nil {
		return errors.New("unable to find device for user (challenge)")
	}

	if subtle.ConstantTimeCompare([]byte(dc.Challenge), []byte(device.Challenge)) != 0 {
		return errors.New("device challenge did not match device stored challenge")
	}

	return nil
}

func (d Device) ChallengeExists() error {
	_, err := get[DeviceChallenge](DeviceChallengePrefix + d.Username + "-" + d.Address)
	return err
}

func (d Device) GetSensitiveChallenge() (string, error) {
	deviceWithChallenge, err := get[Device](DevicesPrefix + d.Username + "-" + d.Address)

	return deviceWithChallenge.Challenge, err
}

func (d Device) SetChallenge() error {

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
func UpdateDeviceConnectionDetails(address string, endpoint *net.UDPAddr) error {

	realKey, err := etcd.Get(context.Background(), deviceRef+address)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("device was not found")
	}

	return doSafeUpdate(context.Background(), string(realKey.Kvs[0].Value), false, func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		device.Endpoint = endpoint
		device.AssociatedNode = GetServerID()
		device.Challenge, err = utils.GenerateRandomHex(32)
		if err != nil {
			return "", fmt.Errorf("failed to generate random challenge on device authorisation: %s", err)
		}

		b, _ := json.Marshal(device)

		return string(b), err
	})
}

func GetDevice(username, id string) (device Device, err error) {
	return get[Device](deviceKey(username, id))
}

func HasDeviceAuthorised(current, previous Device) bool {
	lockout, err := GetLockout()
	if err != nil {
		return false
	}

	return current.Authorised != previous.Authorised && !current.Authorised.IsZero() && current.Attempts <= lockout && (current.AssociatedNode == previous.AssociatedNode || previous.AssociatedNode == 0)
}

// Set device as authorized and clear authentication attempts
func AuthoriseDevice(username, address string) error {

	err := doSafeUpdate(context.Background(), deviceKey(username, address), false, func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		u, err := GetUserData(device.Username)
		if err != nil {
			// We may want to make this lock the device if the user is not found. At the moment settle with doing nothing
			return "", err
		}

		if u.Locked {
			return "", errors.New("account is locked")
		}

		device.AssociatedNode = GetServerID()
		device.Authorised = time.Now()
		device.Attempts = 0
		device.Challenge, err = utils.GenerateRandomHex(32)
		if err != nil {
			return "", err
		}

		b, _ := json.Marshal(device)

		return string(b), err
	})
	if err != nil {
		return fmt.Errorf("failed to update device authorisation state: %s", err)
	}

	return markDeviceSessionStarted(address, username)
}

type DeviceSession struct {
	Address  string    `json:"address"`
	Username string    `json:"username"`
	Started  time.Time `json:"session_started"`
}

func GetAllSessions() (sessions []DeviceSession, err error) {

	response, err := etcd.Get(context.Background(), DeviceSessionPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	// otherwise json returns null
	sessions = []DeviceSession{}
	for _, res := range response.Kvs {
		var session DeviceSession
		err := json.Unmarshal(res.Value, &session)
		if err != nil {
			return nil, err
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

func markDeviceSessionStarted(address, username string) error {

	ops := []clientv3.OpOption{}

	maxSession, err := GetSessionLifetimeMinutes()
	if err != nil {
		return err
	}

	// sessions are permanently active unless logged out if max Session is disabled
	if maxSession > 0 {
		// turn maxSession into seconds for etcd
		lease, err := clientv3.NewLease(etcd).Grant(context.Background(), int64(maxSession)*60)
		if err != nil {
			return err
		}

		ops = append(ops, clientv3.WithLease(lease.ID))
	}

	var ds DeviceSession
	ds.Address = address
	ds.Username = username
	ds.Started = time.Now()

	b, _ := json.Marshal(ds)

	_, err = etcd.Put(context.Background(), DeviceSessionPrefix+address, string(b), ops...)
	return err
}

func MarkDeviceSessionEnded(address string) error {
	_, err := etcd.Delete(context.Background(), DeviceSessionPrefix+address)
	return err
}

func DeauthenticateDevice(address string) error {

	realKey, err := etcd.Get(context.Background(), deviceRef+address)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("device was not found")
	}

	err = doSafeUpdate(context.Background(), string(realKey.Kvs[0].Value), false, func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		device.Authorised = time.Time{}

		b, _ := json.Marshal(device)

		return string(b), err
	})
	if err != nil {
		return err
	}

	return MarkDeviceSessionEnded(address)
}

func SetDeviceAuthenticationAttempts(username, address string, attempts int) error {
	return doSafeUpdate(context.Background(), deviceKey(username, address), false, func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		device.Attempts = attempts

		b, _ := json.Marshal(device)

		return string(b), err
	})
}

func GetAllDevices() (devices []Device, err error) {

	response, err := etcd.Get(context.Background(), DevicesPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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

	return devices, nil
}

func GetAllDevicesAsMap() (devices map[string]Device, err error) {

	devices = make(map[string]Device)
	response, err := etcd.Get(context.Background(), DevicesPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var device Device
		err := json.Unmarshal(res.Value, &device)
		if err != nil {
			return nil, err
		}

		devices[device.Address] = device
	}

	return devices, nil
}

func AddDevice(username, publickey, staticIp string) (Device, error) {

	preshared_key, err := wgtypes.GenerateKey()
	if err != nil {
		return Device{}, err
	}

	address := staticIp
	if _, err = netip.ParseAddr(staticIp); err != nil || staticIp == "" {
		address, err = getNextIP(config.Values.Wireguard.Address)
		if err != nil {
			return Device{}, err
		}
	}

	d := Device{
		Address:      address,
		Publickey:    publickey,
		Username:     username,
		PresharedKey: preshared_key.String(),
	}

	b, _ := json.Marshal(d)
	key := deviceKey(username, address)

	response, err := etcd.Txn(context.Background()).If(clientv3util.KeyMissing(deviceRef+address)).Then(clientv3.OpPut(key, string(b)),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", address), key),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", publickey), key)).Commit()
	if err != nil {
		return Device{}, err
	}

	if !response.Succeeded {
		return Device{}, fmt.Errorf("device with %q address already exists", address)
	}

	return d, err
}

func SetDevice(username, address, publickey, preshared_key string) (Device, error) {
	if net.ParseIP(address) == nil {
		return Device{}, fmt.Errorf("address %q cannot be parsed as IP, invalid", address)
	}

	d := Device{
		Address:      address,
		Publickey:    publickey,
		Username:     username,
		PresharedKey: preshared_key,
	}

	b, _ := json.Marshal(d)
	key := deviceKey(username, address)

	_, err := etcd.Txn(context.Background()).Then(clientv3.OpPut(key, string(b)),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", address), key),
		clientv3.OpPut(fmt.Sprintf(deviceRef+"%s", publickey), key)).Commit()
	if err != nil {
		return Device{}, err
	}

	return d, err
}

func deviceKey(username, address string) string {
	return fmt.Sprintf("devices-%s-%s", username, address)
}

// DeleteDevice removes a single device from etcd
// username is the users name obviously
// id can be a public key, or ip address
func DeleteDevice(username, id string) error {

	refKey := deviceRef + id

	realKey, err := etcd.Get(context.Background(), refKey)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("no reference found")
	}

	deviceEntry, err := etcd.Get(context.Background(), string(realKey.Kvs[0].Value))
	if err != nil {
		return fmt.Errorf("unable to get real device entry from reference: %s", err)
	}

	var d Device
	err = json.Unmarshal(deviceEntry.Kvs[0].Value, &d)
	if err != nil {
		return err
	}

	_, err = etcd.Txn(context.Background()).Then(deleteDeviceOps(d)...).Commit()

	return err
}

// Generate the operations to delete a device
func deleteDeviceOps(d Device) []clientv3.Op {

	key := deviceKey(d.Username, d.Address)
	ipRef := deviceRef + d.Address
	publicKeyRef := deviceRef + d.Publickey

	sessionRef := DeviceSessionPrefix + d.Address

	challengeKey := DeviceChallengePrefix + d.Username + "-" + d.Address

	return []clientv3.Op{
		clientv3.OpDelete(key),

		clientv3.OpDelete(ipRef),
		clientv3.OpDelete(publicKeyRef),

		clientv3.OpDelete(sessionRef),

		clientv3.OpDelete("allocated_ips/" + d.Address),
		clientv3.OpDelete(challengeKey),
	}
}

func DeleteDevices(username string) error {

	deleted, err := etcd.Delete(context.Background(), fmt.Sprintf("%s%s-", DevicesPrefix, username), clientv3.WithPrefix(), clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	var ops []clientv3.Op
	for _, reference := range deleted.PrevKvs {

		var d Device
		err := json.Unmarshal(reference.Value, &d)
		if err != nil {
			log.Printf("Failed to delete device for user %q, err: %s", username, err)
			continue
		}

		ops = append(ops, deleteDeviceOps(d)...)

	}

	_, err = etcd.Txn(context.Background()).Then(ops...).Commit()
	return err
}

func UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error {

	beforeUpdate, err := GetDeviceByAddress(address)
	if err != nil {
		return err
	}

	err = doSafeUpdate(context.Background(), deviceKey(username, address), false, func(gr *clientv3.GetResponse) (string, error) {
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

	_, err = etcd.Delete(context.Background(), "devicesref-"+beforeUpdate.Publickey)

	return err
}

func GetDeviceByAddress(address string) (device Device, err error) {

	realKey, err := etcd.Get(context.Background(), deviceRef+address)
	if err != nil {
		return Device{}, err
	}

	if len(realKey.Kvs) == 0 {
		return Device{}, errors.New("not device found for address: " + address)
	}

	if len(realKey.Kvs) != 1 {
		return Device{}, errors.New("incorrect number of keys for device reference")
	}

	response, err := etcd.Get(context.Background(), string(realKey.Kvs[0].Value))
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

func GetDevicesByUser(username string) (devices []Device, err error) {

	response, err := etcd.Get(context.Background(), fmt.Sprintf("devices-%s-", username), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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
