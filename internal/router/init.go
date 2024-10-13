package router

import (
	"fmt"
	"log"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

func New(iptables bool) (*Firewall, error) {

	log.Println("[ROUTER] Starting up")
	var fw Firewall
	initialUsers, knownDevices, err := data.GetInitialData()
	if err != nil {
		return nil, fmt.Errorf("[ROUTER] failed to get users and devices from etcd: %s", err)
	}

	log.Println("[ROUTER] Adding users")

	err = fw.setupUsers(initialUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to setup users: %s")
	}

	log.Println("[ROUTER] Adding wireguard devices")
	err = fw.setupDevices(knownDevices)
	if err != nil {
		return nil, fmt.Errorf("failed to setup devices: %s")
	}

	log.Println("[ROUTER] Registering event handlers")
	err = fw.handleEvents()
	if err != nil {
		return nil, fmt.Errorf("failed to start handling etcd events: %s")
	}

	if iptables {

		routeMode := "MASQUERADE (NAT)"
		if config.Values.NAT != nil && !*config.Values.NAT {
			routeMode = "RAW (No NAT)"
		}

		log.Printf("[ROUTER] Setting up iptables in %s mode", routeMode)

		err := fw.setupIptables()
		if err != nil {
			return nil, fmt.Errorf("failed to start handling etcd events: %s")
		}
	}
	return &fw, nil
}

func (f *Firewall) Close() {
	f.Lock()
	defer f.Unlock()

	log.Println("Removing handlers")
	f.deregisterEventHandlers()

	log.Println("Removing wireguard device")
	if f.device != nil {
		f.device.Close()
	}

	if f.ctrl != nil {
		f.ctrl.Close()
	}

	log.Println("Wireguard device removed")

	log.Println("Removing Firewall rules...")
	f.teardownIptables()

	f.closed = true
}
