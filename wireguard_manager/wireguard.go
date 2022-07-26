package wireguard_manager

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"
	"wag/utils"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ctrl *wgctrl.Client
var wgDevName string
var vpnRange *net.IPNet

func StartEndpointWatcher(deviceName string, vpnnet *net.IPNet, Ctrl *wgctrl.Client, endpointChanges chan<- net.IP, errChan chan<- error) {
	ctrl = Ctrl
	wgDevName = deviceName
	vpnRange = vpnnet

	go func() {
		var endpoints = map[wgtypes.Key]*net.UDPAddr{}

		startup := true

		for {
			dev, err := ctrl.Device(wgDevName)
			if err != nil {
				errChan <- fmt.Errorf("Wireguard endpoint watcher failed: %v", err)
				return
			}

			for _, p := range dev.Peers {
				previousAddress := endpoints[p.PublicKey]

				if len(p.AllowedIPs) != 1 {
					log.Println("Warning, peer ", p.PublicKey.String(), " len(p.AllowedIPs) != 1, which is not supported")
					continue
				}

				if previousAddress.String() != p.Endpoint.String() {

					endpoints[p.PublicKey] = p.Endpoint

					//Dont try and remove rules, if we've just started
					if !startup {
						endpointChanges <- p.AllowedIPs[0].IP
					}
				}

			}

			startup = false

			time.Sleep(100 * time.Millisecond)
		}
	}()

}

func RemoveDevice(public wgtypes.Key) error {

	var c wgtypes.Config
	c.Peers = append(c.Peers, wgtypes.PeerConfig{
		PublicKey: public,
		Remove:    true,
	})

	return ctrl.ConfigureDevice(wgDevName, c)
}

// Add the device to wireguard
func AddDevice(public wgtypes.Key) (string, error) {

	dev, err := ctrl.Device(wgDevName)
	if err != nil {
		return "", err
	}

	//Poor selection algorithm

	//If we dont have any peers take the server tun address and increment that
	newAddress := vpnRange.IP.String()
	if len(dev.Peers) > 0 {
		addresses := []string{}
		for _, peer := range dev.Peers {
			addresses = append(addresses, utils.GetIP(peer.AllowedIPs[0].IP.String()))
		}

		newAddress = addresses[len(addresses)-1]
	}

	newAddress, err = utils.IncrementIP(newAddress, vpnRange.String())
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

	return network.IP.String(), ctrl.ConfigureDevice(wgDevName, c)
}

func GetDevice(address string) (wgtypes.Key, error) {
	dev, err := ctrl.Device(wgDevName)
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
