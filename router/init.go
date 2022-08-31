package router

import (
	"fmt"
	"log"
	"net"
	"time"
	"wag/config"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Setup(error chan<- error) (err error) {
	err = setupIptables()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			TearDown()
		}
	}()

	err = setupXDP()
	if err != nil {
		return err
	}

	ctrl, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("cannot start wireguard control %v", err)
	}

	endpointChanges := make(chan net.IP)

	go func() {
		for ip := range endpointChanges {
			log.Println("Endpoint change, removing invalidating 2fa for: ", ip)
			if err := Deauthenticate(ip.String()); err != nil {
				log.Println("Unable to remove forwards for device: ", err)
			}
		}
	}()

	go func() {
		startup := true
		var endpoints = map[wgtypes.Key]*net.UDPAddr{}

		for {

			dev, err := ctrl.Device(config.Values().WgDevName)
			if err != nil {
				error <- fmt.Errorf("endpoint watcher: %s", err)
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

	log.Println("Started firewall management: \n",
		"\t\t\tSetting filter FORWARD policy to DROP\n",
		"\t\t\tAllowed input on tunnel port\n",
		"\t\t\tSet MASQUERADE\n",
		"\t\t\tXDP eBPF program managing firewall\n",
		"\t\t\tSet public forwards")

	return nil
}
