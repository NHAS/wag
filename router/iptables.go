package router

import (
	"github.com/NHAS/wag/config"

	"github.com/coreos/go-iptables/iptables"
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

	err = ipt.Append("filter", "FORWARD", "-i", config.Values().Wireguard.DevName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("nat", "POSTROUTING", "-s", config.Values().Wireguard.Range.String(), "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values().Wireguard.DevName, "--dport", config.Values().Webserver.Tunnel.Port, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-p", "icmp", "--icmp-type", "8", "-i", config.Values().Wireguard.DevName, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().Wireguard.DevName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().Wireguard.DevName, "-j", "DROP")
	if err != nil {
		return err
	}

	return nil
}
