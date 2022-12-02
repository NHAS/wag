package users

import (
	"fmt"
	"testing"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func setupWgTest() error {
	if err := config.Load("../config/test_in_memory_db.json"); err != nil {
		return err
	}

	err := data.Load(config.Values().DatabaseLocation)
	if err != nil {
		return fmt.Errorf("cannot load database: %v", err)
	}

	errChan := make(chan error)

	return router.Setup(errChan, false)
}

func TestCreateUser(t *testing.T) {
	err := setupWgTest()
	if err != nil {
		t.Fatalf("failed to setup wg: %s", err)
	}
	defer router.TearDown()

	user, err := CreateUser("fronk")
	if err != nil {
		t.Fatal("could not make user:", err)
	}

	if user.Username != "fronk" {
		t.Fatal("usernames not equal")
	}

	if user.Enforcing {
		t.Fatal("initally users should not be enforcing")
	}

	if user.Locked {
		t.Fatal("initally users should not be locked")
	}

	devices, err := user.GetDevices()
	if err != nil {
		t.Fatal("could not get device: ", err)
	}

	if len(devices) != 0 {
		t.Fatal("initally created user should not have devices")
	}

}

func TestAddDevice(t *testing.T) {
	err := setupWgTest()
	if err != nil {
		t.Fatalf("failed to setup wg: %s", err)
	}
	defer router.TearDown()

	user, err := CreateUser("fronk")
	if err != nil {
		t.Fatal("could not make user:", err)
	}

	pubkey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	device, err := user.AddDevice(pubkey)
	if err != nil {
		t.Fatal("unable to add device:", err)
	}

	if device.Publickey != pubkey.String() {
		t.Fatal("stored and returned public key not equal")
	}

	newDevice, err := user.GetDevice(device.Address)
	if err != nil {
		t.Fatal("unable to get device:", err)
	}

	if newDevice.Address != device.Address || newDevice.Publickey != device.Publickey {
		t.Fatal("returned device incorrect:", err)
	}

}

func TestDeleteDevice(t *testing.T) {
	err := setupWgTest()
	if err != nil {
		t.Fatalf("failed to setup wg: %s", err)
	}
	defer router.TearDown()

	user, err := CreateUser("fronk")
	if err != nil {
		t.Fatal("could not make user:", err)
	}

	pubkey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	device, err := user.AddDevice(pubkey)
	if err != nil {
		t.Fatal("unable to add device:", err)
	}

	err = user.DeleteDevice(device.Address)
	if err != nil {
		t.Fatal("unable to delete device:", err)
	}

	devices, err := data.GetAllDevices()
	if err != nil {
		t.Fatal("unable to get all devices:", err)
	}

	if len(devices) != 0 {
		t.Fatal("removed only device, should be no devices left in db")
	}
}

func TestDeleteUser(t *testing.T) {
	err := setupWgTest()
	if err != nil {
		t.Fatalf("failed to setup wg: %s", err)
	}

	user, err := CreateUser("fronk")
	if err != nil {
		t.Fatal("could not make user:", err)
	}

	pubkey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = user.AddDevice(pubkey)
	if err != nil {
		t.Fatal("unable to add device:", err)
	}

	pubkey2, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = user.AddDevice(pubkey2)
	if err != nil {
		t.Fatal("unable to add device:", err)
	}

	err = user.Delete()
	if err != nil {
		t.Fatal("unable to user:", err)
	}

	devices, err := data.GetAllDevices()
	if err != nil {
		t.Fatal("unable to get all devices:", err)
	}

	if len(devices) != 0 {
		t.Fatal("removed only user, should be no devices left in db")
	}

	users, err := data.GetAllUsers()
	if err != nil {
		t.Fatal("unable to get all users:", err)
	}

	if len(users) != 0 {
		t.Fatal("removed only user, should be no users left in db")
	}
}
