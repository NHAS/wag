package router

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/interfaces"
	"golang.zx2c4.com/wireguard/tun"
)

func New(db interfaces.Database, iptables bool) (*Firewall, error) {
	return newFw(db, false, iptables, nil)
}

func newFw(db interfaces.Database, testing, iptables bool, testDev tun.Device) (fw *Firewall, err error) {

	log.Info().Msg("Starting up")

	fw = &Firewall{
		userPolicies: make(map[string]*Policies),
		userIsLocked: make(map[string]bool),

		addressToDevice:   make(map[netip.Addr]*FirewallDevice),
		addressToPolicies: make(map[netip.Addr]*Policies),

		addressToUser:  make(map[netip.Addr]string),
		userToDevices:  make(map[string]map[string]*FirewallDevice),
		pubkeyToDevice: make(map[string]*FirewallDevice),

		currentlyConnectedPeers: make(map[string]string),
		hasIptables:             iptables,

		db: db,
	}

	inactivityTimeoutInt, err := db.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return nil, fmt.Errorf("failed to get session inactivity timeout: %s", err)
	}

	if inactivityTimeoutInt > 0 {
		fw.inactivityTimeout = time.Duration(inactivityTimeoutInt) * time.Minute
	} else {
		fw.inactivityTimeout = -1
	}

	fw.nodeID = db.GetCurrentNodeID()
	fw.deviceName = config.Values.Wireguard.DevName

	initialUsers, knownDevices, err := db.GetInitialData()
	if err != nil {
		return nil, fmt.Errorf("[ROUTER] failed to get users and devices from etcd: %s", err)
	}

	if testing {
		err = fw.setupWireguardDebug(testDev)
	} else {
		err = fw.setupWireguard(config.Values.Wireguard.DevName, config.Values.Wireguard.Address, config.Values.Wireguard.MTU)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard device: err: %s", err)
	}

	log.Info().Msg("Adding users")

	err = fw.setupUsers(initialUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to setup users: %s", err)
	}

	log.Info().Msg("Adding wireguard devices")

	err = fw.setupDevices(knownDevices)
	if err != nil {
		return nil, fmt.Errorf("failed to setup devices: %s", err)
	}

	if fw.hasIptables {

		routeMode := "MASQUERADE (NAT)"
		if config.Values.NAT != nil && !*config.Values.NAT {
			routeMode = "RAW (No NAT)"
		}

		log.Info().Str("mode", routeMode).Msg("Setting up iptables")

		err := fw.setupIptables()
		if err != nil {
			return nil, fmt.Errorf("failed to initialise iptables: %s", err)
		}
	}

	log.Info().Msg("Registering event handlers")

	// This must be the last thing that occurs otherwise we may get events before we're ready to serve them
	err = fw.handleEvents()
	if err != nil {
		return nil, fmt.Errorf("failed to start handling etcd events: %s", err)
	}

	log.Info().Msg("Setup finished")

	return fw, nil
}

func (f *Firewall) Close() {
	f.Lock()
	defer f.Unlock()

	log.Info().Msg("Removing handlers")
	for _, w := range f.watchers {
		w.Close()
	}

	log.Info().Msg("Removing wireguard device")
	if f.device != nil {
		f.device.Close()
	}

	if f.ctrl != nil {
		f.ctrl.Close()
	}

	log.Info().Msg("Wireguard device removed")

	if f.hasIptables {
		f.teardownIptables()
	}
	f.closed = true
}
