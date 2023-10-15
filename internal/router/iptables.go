package router

import (
	"errors"
	"strings"

	"github.com/NHAS/wag/internal/config"

	"github.com/coreos/go-iptables/iptables"
)

func setupIptables() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	devName := config.Values().Wireguard.DevName

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

	err = ipt.Append("filter", "FORWARD", "-i", devName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-o", devName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	shouldNAT := config.Values().NAT == nil || (config.Values().NAT != nil && *config.Values().NAT)
	if shouldNAT {
		err = ipt.Append("nat", "POSTROUTING", "-s", config.Values().Wireguard.Range.String(), "-j", "MASQUERADE")
		if err != nil {
			return err
		}
	}

	if !config.Values().Proxied {
		//Allow input to authorize web server on the tunnel, if we're not behind a proxy
		err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", devName, "--dport", config.Values().Webserver.Tunnel.Port, "-j", "ACCEPT")
		if err != nil {
			return err
		}

		// Open port 80 to allow http redirection
		if config.Values().Webserver.Tunnel.SupportsTLS() {
			//Allow input to authorize web server on the tunnel (http -> https redirect), if we're not behind a proxy
			err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", devName, "--dport", "80", "-j", "ACCEPT")
			if err != nil {
				return err
			}
		}

	}

	for _, port := range config.Values().ExposePorts {
		parts := strings.Split(port, "/")
		if len(parts) < 2 {
			return errors.New(port + " is not in a valid port format. E.g 80/tcp")
		}

		err = ipt.Append("filter", "INPUT", "-m", parts[1], "-p", parts[1], "-i", devName, "--dport", strings.Replace(parts[0], "-", ":", 1), "-j", "ACCEPT")
		if err != nil {
			return err
		}
	}

	err = ipt.Append("filter", "INPUT", "-p", "icmp", "--icmp-type", "8", "-i", devName, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", devName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", devName, "-j", "DROP")
	if err != nil {
		return err
	}

	return nil
}
