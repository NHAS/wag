package router

import (
	"fmt"
	"net"
	"testing"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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

	err = setupWireguard()
	if err != nil {
		return fmt.Errorf("cannot setup wireguard: %v", err)
	}

	err = setupXDP()
	if err != nil {
		return err
	}

	return nil
}

func TestWgLoadBasic(t *testing.T) {

	err := setupWgTest()
	if err != nil {
		t.Fatal(err)
	}

	i, err := net.InterfaceByName(config.Values().Wireguard.DevName)
	if err != nil {
		t.Fatal("interface was not actually create despite setupWireguard not failing")
	}

	if i.MTU != config.Values().Wireguard.MTU {
		t.Fatal("device settings are not correct (MTU)")
	}

	addrs, err := i.Addrs()
	if err != nil {
		t.Fatal("unable to get device addresses: ", err)
	}

	if len(addrs) != 1 {
		t.Fatal("the device does not have the expected numer of ip addresses: ", len(addrs))
	}

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.Fatal("Unable to remove wireguard device, netlink connection failed: ", err.Error())
	}
	defer conn.Close()

	err = delWg(conn, config.Values().Wireguard.DevName)
	if err != nil {
		t.Fatal("Unable to remove wireguard device, delete failed: ", err.Error())
	}

}

func TestWgAddRemove(t *testing.T) {
	err := setupWgTest()
	if err != nil {
		t.Fatal(err)
	}

	pk, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = AddUser("toaster", config.Acl{})
	if err != nil {
		t.Fatal(err)
	}

	address, _, err := AddPeer(pk, "toaster")
	if err != nil {
		t.Fatal(err)
	}

	if address != "10.2.43.2" {
		t.Fatal("address of added peer did not match expected: ", address)
	}

	dev, err := ctrl.Device(config.Values().Wireguard.DevName)
	if err != nil {
		t.Fatal("could not connect to wireguard device to check the details there")
	}

	if len(dev.Peers) != 1 {
		t.Fatal("Added one device, didnt get 1 device back from the wg device")
	}

	if dev.Peers[0].PublicKey.String() != pk.String() {
		t.Fatal("The peer added to the wg device did not have the correct pulic key")
	}

	if len(dev.Peers[0].AllowedIPs) != 1 {
		t.Fatal("the peer did not have only 1 ip address")
	}

	if dev.Peers[0].AllowedIPs[0].IP.String() != "10.2.43.2" {
		t.Fatal("the peer did have the same ip address as what was added: ", dev.Peers[0].AllowedIPs[0].IP.String())
	}

	err = RemovePeer(pk.String(), address)
	if err != nil {
		t.Fatal(err)
	}

	dev, err = ctrl.Device(config.Values().Wireguard.DevName)
	if err != nil {
		t.Fatal("could not connect to wireguard device to check the details there")
	}

	if len(dev.Peers) != 0 {
		t.Fatal("Removed only device the wireguard device was not informed")
	}

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.Fatal("Unable to remove wireguard device, netlink connection failed: ", err.Error())
	}
	defer conn.Close()

	err = delWg(conn, config.Values().Wireguard.DevName)
	if err != nil {
		t.Fatal("Unable to remove wireguard device, delete failed: ", err.Error())
	}
}
