package router

import (
	"fmt"
	"log"
	"strings"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

var (
	globalFirewall *Firewall
)

func NewFirewall(iptables bool) (*Firewall, error) {

	m := &Firewall{}
	initialUsers, knownDevices, err := data.GetInitialData()
	if err != nil {
		return nil, fmt.Errorf("failed to get users and devices from etcd: %s", err)
	}

	err = m.setupUsers(initialUsers)
	if err != nil {
		return nil, err
	}

	err = m.setupDevices(knownDevices)
	if err != nil {
		return nil, err
	}

	err = m.handleEvents()
	if err != nil {
		return nil, err
	}

	return m, nil
}

func Setup(errorChan chan<- error, iptables bool) (err error) {

	if globalFirewall != nil {
		globalFirewall.TearDown()
	}

	globalFirewall, err = NewFirewall(iptables)
	if err != nil {
		return err
	}

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

func (f *Firewall) TearDown() {

	log.Println("Removing wireguard device")
	if f.device != nil {
		f.device.Close()
	}

	if f.ctrl != nil {
		f.ctrl.Close()
	}

	log.Println("Wireguard device removed")

	log.Println("Removing Firewall rules...")
	teardownIptables()

}
