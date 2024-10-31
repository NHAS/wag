package router

import (
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"golang.zx2c4.com/wireguard/tun"
)

func newDebugFirewall(testDev tun.Device) (*Firewall, error) {
	return newFw(true, false, testDev)

}

func New(iptables bool) (*Firewall, error) {
	return newFw(false, iptables, nil)
}

func newFw(testing, iptables bool, testDev tun.Device) (*Firewall, error) {
	log.Println("[ROUTER] Starting up")
	fw := Firewall{
		userPolicies: make(map[string]*Policies),
		userIsLocked: make(map[string]bool),

		addressToDevice:   make(map[netip.Addr]*FirewallDevice),
		addressToPolicies: make(map[netip.Addr]*Policies),

		addressToUser:  make(map[netip.Addr]string),
		userToDevices:  make(map[string]map[string]*FirewallDevice),
		pubkeyToDevice: make(map[string]*FirewallDevice),

		currentlyConnectedPeers: make(map[string]string),
		hasIptables:             iptables,
	}

	inactivityTimeoutInt, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return nil, fmt.Errorf("failed to get session inactivity timeout: %s", err)
	}

	if inactivityTimeoutInt > 0 {
		fw.inactivityTimeout = time.Duration(inactivityTimeoutInt) * time.Minute
	} else {
		fw.inactivityTimeout = -1
	}

	fw.nodeID = data.GetServerID()
	fw.deviceName = config.Values.Wireguard.DevName

	initialUsers, knownDevices, err := data.GetInitialData()
	if err != nil {
		return nil, fmt.Errorf("[ROUTER] failed to get users and devices from etcd: %s", err)
	}

	if testing {
		err = fw.setupWireguardDebug(testDev)
	} else {
		err = fw.setupWireguard(config.Values.Wireguard.Address, config.Values.Wireguard.DevName, config.Values.Wireguard.MTU)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard device: err: %s", err)
	}

	log.Println("[ROUTER] Adding users")

	err = fw.setupUsers(initialUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to setup users: %s", err)
	}

	log.Println("[ROUTER] Adding wireguard devices")
	err = fw.setupDevices(knownDevices)
	if err != nil {
		return nil, fmt.Errorf("failed to setup devices: %s", err)
	}

	log.Println("[ROUTER] Registering event handlers")
	err = fw.handleEvents()
	if err != nil {
		return nil, fmt.Errorf("failed to start handling etcd events: %s", err)
	}

	if fw.hasIptables {

		routeMode := "MASQUERADE (NAT)"
		if config.Values.NAT != nil && !*config.Values.NAT {
			routeMode = "RAW (No NAT)"
		}

		log.Printf("[ROUTER] Setting up iptables in %s mode", routeMode)

		err := fw.setupIptables()
		if err != nil {
			return nil, fmt.Errorf("failed to start handling etcd events: %s", err)
		}
	}

	fw.Verifier = NewChallenger()

	log.Println("[ROUTER] Setup finished")

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

	if f.hasIptables {
		f.teardownIptables()
	}
	f.closed = true
}
