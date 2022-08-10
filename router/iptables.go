package router

import (
	"log"
	"sync"
	"wag/config"

	"github.com/coreos/go-iptables/iptables"
)

var (
	l          sync.RWMutex
	sessions   = map[string]string{}
	tunnelPort string
)

func setupIptables() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	//So. This to the average person will look like we say "Hey server forward anything and everything from the wireguard interface"
	//And without the xdp ebpf program it would be, however if you look at xdp.c you can see that we can manipluate maps of addresses for each user
	//This then controls whether the packet is dropped, but we still need iptables to do the higher level routing stuffs

	err = ipt.ChangePolicy("filter", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-i", config.Values().WgDevName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("nat", "POSTROUTING", "-s", config.Values().VPNRange.String(), "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values().WgDevName, "--dport", tunnelPort, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "DROP")
	if err != nil {
		return err
	}

	return nil
}

func GetAllAllowed() map[string]string {
	l.RLock()
	defer l.RUnlock()

	out := map[string]string{}
	for k, v := range sessions {
		out[k] = v
	}

	return out
}

func IsAlreadyAuthed(address string) string {
	l.RLock()
	defer l.RUnlock()

	output := sessions[address]

	return output
}

func TearDown() {
	log.Println("Removing Firewall rules...")

	ipt, err := iptables.New()
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
		return
	}

	err = ipt.Delete("filter", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	//Setup the links to the new chains
	err = ipt.Delete("filter", "FORWARD", "-i", config.Values().WgDevName, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("nat", "POSTROUTING", "-s", config.Values().VPNRange.String(), "-j", "MASQUERADE")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Delete("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values().WgDevName, "--dport", tunnelPort, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "DROP")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

}
