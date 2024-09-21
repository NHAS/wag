package router

import (
	"errors"
	"log"
	"strings"

	"github.com/NHAS/wag/internal/config"

	"github.com/coreos/go-iptables/iptables"
)

func (f *Firewall) setupIptables() error {
	f.Lock()
	defer f.Unlock()

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	devName := config.Values.Wireguard.DevName

	//So. This to the average person will look like we say "Hey server forward anything and everything from the wireguard interface"
	//And without the xdp ebpf program it would be, however if you look at xdp.c you can see that we can manipulate maps of addresses for each user
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

	shouldNAT := config.Values.NAT == nil || (config.Values.NAT != nil && *config.Values.NAT)
	if shouldNAT {
		err = ipt.Append("nat", "POSTROUTING", "-s", config.Values.Wireguard.Range.String(), "-j", "MASQUERADE")
		if err != nil {
			return err
		}
	}

	if config.Values.NumberProxies == 0 {
		//Allow input to authorize web server on the tunnel, if we're not behind a proxy
		err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", devName, "--dport", config.Values.Webserver.Tunnel.Port, "-j", "ACCEPT")
		if err != nil {
			return err
		}

		// Open port 80 to allow http redirection
		if config.Values.Webserver.Tunnel.SupportsTLS() {
			//Allow input to authorize web server on the tunnel (http -> https redirect), if we're not behind a proxy
			err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", devName, "--dport", "80", "-j", "ACCEPT")
			if err != nil {
				return err
			}
		}

	}

	for _, port := range config.Values.ExposePorts {
		parts := strings.Split(port, "/")
		if len(parts) < 2 {
			return errors.New(port + " is not in a valid port format. E.g 80/tcp or 80-100/tcp")
		}

		err = ipt.Append("filter", "INPUT", "-m", parts[1], "-p", parts[1], "-i", devName, "--dport", strings.Replace(parts[0], "-", ":", 1), "-j", "ACCEPT")
		if err != nil {
			return err
		}
	}

	err = ipt.Append("filter", "INPUT", "-p", "icmp", "-i", devName, "-j", "ACCEPT")
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

func teardownIptables() {
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
	err = ipt.Delete("filter", "FORWARD", "-i", config.Values.Wireguard.DevName, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "FORWARD", "-o", config.Values.Wireguard.DevName, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	shouldNAT := config.Values.NAT == nil || (config.Values.NAT != nil && *config.Values.NAT)
	if shouldNAT {
		err = ipt.Delete("nat", "POSTROUTING", "-s", config.Values.Wireguard.Range.String(), "-j", "MASQUERADE")
		if err != nil {
			log.Println("Unable to clean up firewall rules: ", err)
		}
	}

	if config.Values.NumberProxies == 0 {
		//Allow input to authorize web server on the tunnel
		err = ipt.Delete("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values.Wireguard.DevName, "--dport", config.Values.Webserver.Tunnel.Port, "-j", "ACCEPT")
		if err != nil {
			log.Println("Unable to clean up firewall rules: ", err)
		}

		// Open port 80 to allow http redirection
		if config.Values.Webserver.Tunnel.SupportsTLS() {
			//Allow input to authorize web server on the tunnel (http -> https redirect), if we're not behind a proxy
			err = ipt.Delete("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values.Wireguard.DevName, "--dport", "80", "-j", "ACCEPT")
			if err != nil {
				log.Println("Unable to clean up firewall rules: ", err)
			}
		}
	}

	for _, port := range config.Values.ExposePorts {
		parts := strings.Split(port, "/")
		if len(parts) < 2 {
			log.Println(port + " is not in a valid port format. E.g 80/tcp, 100-200/tcp")
		}

		err = ipt.Delete("filter", "INPUT", "-m", parts[1], "-p", parts[1], "-i", config.Values.Wireguard.DevName, "--dport", strings.Replace(parts[0], "-", ":", 1), "-j", "ACCEPT")
		if err != nil {
			log.Println("unable to cleanup custom defined port", port, ":", err)
		}
	}

	err = ipt.Delete("filter", "INPUT", "-p", "icmp", "-i", config.Values.Wireguard.DevName, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values.Wireguard.DevName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values.Wireguard.DevName, "-j", "DROP")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	log.Println("Firewall rules removed.")
}
