package main

import (
	"errors"
	"log"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func WireguardEndpointWatcher(Ctrl *wgctrl.Client, endpointChanges chan<- net.IP) error {

	var endpoints = map[wgtypes.Key]*net.UDPAddr{}

	for {
		dev, err := Ctrl.Device(Config.WgDevName)
		if err != nil {
			return err
		}

		for _, p := range dev.Peers {
			previousAddress := endpoints[p.PublicKey]

			if len(p.AllowedIPs) != 1 {
				log.Println("Warning, peer ", p.PublicKey.String(), " len(p.AllowedIPs) != 1, which is not supported")
				continue
			}

			if previousAddress.String() != p.Endpoint.String() {

				endpoints[p.PublicKey] = p.Endpoint

				endpointChanges <- p.AllowedIPs[0].IP
			}

		}

		time.Sleep(100 * time.Millisecond)
	}

}

func RemoveDevice(public wgtypes.Key) error {

	var c wgtypes.Config
	c.Peers = append(c.Peers, wgtypes.PeerConfig{
		PublicKey: public,
		Remove:    true,
	})

	return Ctrl.ConfigureDevice(Config.WgDevName, c)
}

// Add the device to wireguard
func AddDevice(public wgtypes.Key) (string, error) {

	dev, err := Ctrl.Device(Config.WgDevName)
	if err != nil {
		return "", err
	}

	//Poor selection algorithm
	newAddress := Config.StartingAddress
	if len(dev.Peers) > 0 {
		addresses := []string{}
		for _, peer := range dev.Peers {
			addresses = append(addresses, GetIP(peer.AllowedIPs[0].IP.String()))
		}

		newAddress = addresses[len(addresses)-1]
	}

	newAddress, err = incrementIP(newAddress, Config.InternalRange)
	if err != nil {
		return "", err
	}

	_, network, err := net.ParseCIDR(newAddress + "/32")
	if err != nil {
		return "", err
	}

	var c wgtypes.Config
	c.Peers = append(c.Peers, wgtypes.PeerConfig{
		PublicKey:         public,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*network},
	})

	return network.IP.String(), Ctrl.ConfigureDevice(Config.WgDevName, c)
}

func GetDevice(address string) (wgtypes.Key, error) {
	dev, err := Ctrl.Device(Config.WgDevName)
	if err != nil {
		return wgtypes.Key{}, err
	}

	for _, peer := range dev.Peers {
		if len(peer.AllowedIPs) == 1 && peer.AllowedIPs[0].IP.String() == address {
			return peer.PublicKey, nil
		}
	}

	return wgtypes.Key{}, errors.New("Not found")
}
