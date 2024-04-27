package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/NHAS/wag/internal/config"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Device struct {
	Version      int
	Address      string
	Publickey    string
	Username     string
	PresharedKey string
	Endpoint     *net.UDPAddr
	Attempts     int
	Active       bool
	Authorised   time.Time
}

func (d Device) String() string {

	authorised := "no"
	if !d.Authorised.Equal(time.Time{}) {
		authorised = d.Authorised.Format(time.DateTime)
	}

	return fmt.Sprintf("device[%s:%s][active: %t, attempts: %d, authorised: %s]", d.Username, d.Address, d.Active, d.Attempts, authorised)
}

func UpdateDeviceEndpoint(address string, endpoint *net.UDPAddr) error {

	realKey, err := etcd.Get(context.Background(), "deviceref-"+address)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("device was not found")
	}

	return doSafeUpdate(context.Background(), string(realKey.Kvs[0].Value), func(gr *clientv3.GetResponse) (string, error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("user device has multiple keys")
		}

		var device Device
		err := json.Unmarshal(gr.Kvs[0].Value, &device)
		if err != nil {
			return "", err
		}

		device.Endpoint = endpoint

		b, _ := json.Marshal(device)

		return string(b), err
	})
}

func GetDevice(username, id string) (device Device, err error) {

	response, err := etcd.Get(context.Background(), deviceKey(username, id))
	if err != nil {
		return Device{}, err
	}

	if response.Count == 0 {
		return Device{}, errors.New("device was not found")
	}

	if len(response.Kvs) != 1 {
		return Device{}, errors.New("user device has multiple keys")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &device)

	return
}

// Set device as authorized and clear authentication attempts
func AuthoriseDevice(username, address string) error {
	return doSafeUpdate(context.Background(), deviceKey(username, address), func(gr *clientv3.GetResponse) (string, error) {
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

		device.Authorised = time.Now()
		device.Attempts = 0

		b, _ := json.Marshal(device)

		return string(b), err
	})
}

func DeauthenticateDevice(address string) error {

	realKey, err := etcd.Get(context.Background(), "deviceref-"+address)
	if err != nil {
		return err
	}

	if realKey.Count == 0 {
		return errors.New("device was not found")
	}

	var realDeviceAddr string
	json.Unmarshal(realKey.Kvs[0].Value, &realDeviceAddr)

	return doSafeUpdate(context.Background(), realDeviceAddr, func(gr *clientv3.GetResponse) (string, error) {
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
}

func SetDeviceAuthenticationAttempts(username, address string, attempts int) error {
	return doSafeUpdate(context.Background(), deviceKey(username, address), func(gr *clientv3.GetResponse) (string, error) {
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

	response, err := etcd.Get(context.Background(), "devices-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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

func AddDevice(username, publickey string) (Device, error) {

	preshared_key, err := wgtypes.GenerateKey()
	if err != nil {
		return Device{}, err
	}

	address, err := getNextIP(config.Values.Wireguard.Range.String())
	if err != nil {
		return Device{}, err
	}

	d := Device{
		Address:      address,
		Publickey:    publickey,
		Username:     username,
		PresharedKey: preshared_key.String(),
	}

	b, _ := json.Marshal(d)
	key := deviceKey(username, address)

	_, err = etcd.Txn(context.Background()).Then(clientv3.OpPut(key, string(b)),
		clientv3.OpPut(fmt.Sprintf("deviceref-%s", address), key),
		clientv3.OpPut(fmt.Sprintf("deviceref-%s", publickey), key)).Commit()
	if err != nil {
		return Device{}, err
	}

	return d, err
}

func SetDevice(username, address, publickey, preshared_key string) (Device, error) {
	if net.ParseIP(address) == nil {
		return Device{}, errors.New("Address '" + address + "' cannot be parsed as IP, invalid")
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
		clientv3.OpPut(fmt.Sprintf("deviceref-%s", address), key),
		clientv3.OpPut(fmt.Sprintf("deviceref-%s", publickey), key)).Commit()
	if err != nil {
		return Device{}, err
	}

	return d, err
}

func deviceKey(username, address string) string {
	return fmt.Sprintf("devices-%s-%s", username, address)
}

func DeleteDevice(username, id string) error {

	refKey := "deviceref-" + id

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

	otherReferenceKey := "deviceref-" + d.Publickey
	if d.Publickey == id {
		otherReferenceKey = "deviceref-" + d.Address
	}

	_, err = etcd.Txn(context.Background()).Then(clientv3.OpDelete(string(realKey.Kvs[0].Value)), clientv3.OpDelete(refKey), clientv3.OpDelete(otherReferenceKey), clientv3.OpDelete("allocated_ips/"+d.Address)).Commit()
	if err != nil {
		return err
	}

	return err
}

func DeleteDevices(username string) error {

	deleted, err := etcd.Delete(context.Background(), fmt.Sprintf("devices-%s-", username), clientv3.WithPrefix())
	if err != nil {
		return err
	}

	ops := []clientv3.Op{}
	for _, reference := range deleted.PrevKvs {

		var d Device
		err := json.Unmarshal(reference.Value, &d)
		if err != nil {
			return err
		}

		ops = append(ops, clientv3.OpDelete("devicesref-"+d.Publickey), clientv3.OpDelete("deviceref-"+d.Address), clientv3.OpDelete("allocated_ips/"+d.Address))
	}

	_, err = etcd.Txn(context.Background()).Then(ops...).Commit()
	return err
}

func UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error {

	beforeUpadte, err := GetDeviceByAddress(address)
	if err != nil {
		return err
	}

	err = doSafeUpdate(context.Background(), deviceKey(username, address), func(gr *clientv3.GetResponse) (string, error) {
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

	_, err = etcd.Delete(context.Background(), "devicesref-"+beforeUpadte.Publickey)

	return err
}

func GetDeviceByAddress(address string) (device Device, err error) {

	realKey, err := etcd.Get(context.Background(), "deviceref-"+address)
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

	if len(response.Kvs) != 1 {
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
