package users

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMain(m *testing.M) {

	err := setupWgTest()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	code := m.Run()
	data.TearDown()

	os.Exit(code)
}

func setupWgTest() error {
	if err := config.Load("../config/testing_config2.json"); err != nil {
		return err
	}

	m, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}

	err = data.Load(fmt.Sprintf("file:%s?mode=memory&cache=shared", m.String()), "", true)
	if err != nil {
		return fmt.Errorf("cannot load database: %v", err)
	}

	errChan := make(chan error)
	err = router.Setup(errChan, false)
	return err
}

func TestCreateUser(t *testing.T) {

	user, err := CreateUser("fronk1")
	if err != nil {
		t.Fatal("could not make user:", err)
	}

	if user.Username != "fronk1" {
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

	user, err := CreateUser("fronk2")
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

	user, err := CreateUser("fronk3")
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

	for _, device := range devices {
		if device.Publickey == pubkey.String() {
			t.Fatal("device with matching public key was found in db")
			return
		}
	}

}

func TestDeleteUser(t *testing.T) {

	user, err := CreateUser("fronk4")
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

	for _, device := range devices {
		if device.Username == "fronk4" {
			t.Fatal("removed fronk4 user, but devices still exist in db for that user")
		}
	}
	users, err := data.GetAllUsers()
	if err != nil {
		t.Fatal("unable to get all users:", err)
	}

	for u := range users {
		if users[u].Username == "fronk4" {
			t.Fatal("removed fronk4 user, but is still present in the db")
		}
	}

}
