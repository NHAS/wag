package router

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	lock   sync.RWMutex
	cancel = make(chan bool)
)

func Setup(errorChan chan<- error, iptables bool) (err error) {

	initialUsers, knownDevices, err := data.GetInitialData()
	if err != nil {
		return errors.New("xdp setup get all users and devices: " + err.Error())
	}

	err = setupWireguard(knownDevices)
	if err != nil {
		return err
	}

	if iptables {
		err = setupIptables()
		if err != nil {
			return err
		}
	}

	err = setupXDP(initialUsers, knownDevices)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			TearDown(true)
		}
	}()

	handleEvents(errorChan)

	go func() {
		ourPeerAddresses := make(map[string]string)
		for {

			select {
			case <-cancel:
				return
			case <-time.After(500 * time.Millisecond):
				dev, err := ctrl.Device(config.Values.Wireguard.DevName)
				if err != nil {
					errorChan <- fmt.Errorf("endpoint watcher: %s", err)
					return
				}

				devices, err := data.GetAllDevicesAsMap()
				if err != nil {
					errorChan <- fmt.Errorf("endpoint watcher: failed to retrieve devices from etcd: %s", err)
					return
				}
				for _, p := range dev.Peers {

					if len(p.AllowedIPs) != 1 {
						log.Println("Warning, peer ", p.PublicKey.String(), " len(p.AllowedIPs) != 1, which is not supported")
						continue
					}

					device, ok := devices[p.AllowedIPs[0].IP.String()]
					if !ok {
						log.Println("found unknown device,", p.AllowedIPs[0].IP.String())
						continue
					}

					// If the peer endpoint has become empty (due to peer roaming) or if we dont have a record of it, set the map
					if _, ok := ourPeerAddresses[device.Address]; !ok || p.Endpoint == nil {
						ourPeerAddresses[device.Address] = p.Endpoint.String()
					}

					// If the peer address has changed, but is not empty (empty indicates the peer has changed it node association away from this node)
					if ourPeerAddresses[device.Address] != p.Endpoint.String() && p.Endpoint != nil {
						ourPeerAddresses[device.Address] = p.Endpoint.String()

						if device.Endpoint.String() != p.Endpoint.String() {
							// This condition will trigger a challenge on the cluster
							log.Printf("%s:%s endpoint changed %s -> %s", device.Address, device.Username, device.Endpoint.String(), p.Endpoint.String())
						}

						// Otherwise, just update the node association
						err = data.UpdateDeviceConnectionDetails(p.AllowedIPs[0].IP.String(), p.Endpoint)
						if err != nil {
							log.Printf("unable to update device (%s:%s) endpoint: %s", device.Address, device.Username, err)
						}

					}

				}
			}

		}
	}()

	output := []string{"Started firewall management: ",
		"\t\t\tSetting filter FORWARD policy to DROP",
		"\t\t\tXDP eBPF program managing firewall",
		"\t\t\tAllow Iptables FORWARDS to and from wireguard device",
		"\t\t\tAllow input to VPN host"}

	routeMode := "MASQUERADE (NAT)"
	if config.Values.NAT != nil && !*config.Values.NAT {
		routeMode = "RAW (No NAT)"
	}

	output = append(output, "\t\t\tSet routing mode to "+routeMode)

	log.Println(strings.Join(output, "\n"))

	return nil
}

func TearDown(force bool) {

	if !force {
		cancel <- true
	}

	log.Println("Removing wireguard device")
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Println("Unable to remove wireguard device, netlink connection failed: ", err.Error())
		return
	}
	defer conn.Close()

	err = delWg(conn, config.Values.Wireguard.DevName)
	if err != nil {
		log.Println("Unable to remove wireguard device, delete failed: ", err.Error())
		return
	}

	log.Println("Wireguard device removed")

	log.Println("Removing Firewall rules...")
	teardownIptables()

}
