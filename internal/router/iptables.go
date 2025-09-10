package router

import (
	"errors"
	"log"
	"strings"

	"github.com/NHAS/wag/internal/config"

	"github.com/coreos/go-iptables/iptables"
)

const (
	filterForwardRulesChain = "WAG_FORWARD_4ede"
	filterInputRulesChain   = "WAG_INPUT_4ede"

	natPostRoutingRulesChain = "WAG_POSTR_4ede"
)

func (f *Firewall) clearChains(ipt *iptables.IPTables) {

	ipt.Delete("filter", "INPUT", "-i", config.Values.Wireguard.DevName, "-j", filterInputRulesChain)

	ipt.Delete("filter", "FORWARD", "-j", filterForwardRulesChain)

	ipt.Delete("nat", "POSTROUTING", "-j", natPostRoutingRulesChain)

	ipt.ClearAndDeleteChain("filter", filterForwardRulesChain)

	ipt.ClearAndDeleteChain("filter", filterInputRulesChain)

	ipt.ClearAndDeleteChain("nat", natPostRoutingRulesChain)
}

func (f *Firewall) setupIptables() error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	var (
		err error
		ipt *iptables.IPTables
	)
	if config.Values.Wireguard.Range.IP.To4() != nil {
		ipt, err = iptables.New()
	} else {
		ipt, err = iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
	}

	if err != nil {
		return err
	}

	devName := config.Values.Wireguard.DevName

	err = ipt.ChangePolicy("filter", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	f.clearChains(ipt)

	err = ipt.NewChain("filter", filterForwardRulesChain)
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterForwardRulesChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterForwardRulesChain, "-i", devName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterForwardRulesChain, "-o", devName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterForwardRulesChain, "-o", devName, "-j", "DROP")
	if err != nil {
		return err
	}

	err = ipt.Insert("filter", "FORWARD", 1, "-j", filterForwardRulesChain)
	if err != nil {
		return err
	}

	shouldNAT := config.Values.NAT == nil || (config.Values.NAT != nil && *config.Values.NAT)
	if shouldNAT {

		err = ipt.NewChain("nat", natPostRoutingRulesChain)
		if err != nil {
			return err
		}

		err = ipt.Append("nat", natPostRoutingRulesChain, "-s", config.Values.Wireguard.Range.String(), "-j", "MASQUERADE")
		if err != nil {
			return err
		}

		err = ipt.Insert("nat", "POSTROUTING", 1, "-j", natPostRoutingRulesChain)
		if err != nil {
			return err
		}
	}

	err = ipt.NewChain("filter", filterInputRulesChain)
	if err != nil {
		return err
	}

	if config.Values.NumberProxies == 0 {
		//Allow input to authorize web server on the tunnel, if we're not behind a proxy
		err = ipt.Append("filter", filterInputRulesChain, "-m", "tcp", "-p", "tcp", "--dport", config.Values.Webserver.Tunnel.Port, "-j", "ACCEPT")
		if err != nil {
			return err
		}

		//Allow input to authorize web server on the tunnel (http -> https redirect), if we're not behind a proxy
		err = ipt.Insert("filter", filterInputRulesChain, 1, "-m", "tcp", "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
		if err != nil {
			return err
		}

	}

	for _, port := range config.Values.ExposePorts {
		parts := strings.Split(port, "/")
		if len(parts) < 2 {
			return errors.New(port + " is not in a valid port format. E.g 80/tcp or 80-100/tcp")
		}

		err = ipt.Append("filter", filterInputRulesChain, "-m", parts[1], "-p", parts[1], "--dport", strings.Replace(parts[0], "-", ":", 1), "-j", "ACCEPT")
		if err != nil {
			return err
		}
	}

	err = ipt.Append("filter", filterInputRulesChain, "-p", "icmp", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterInputRulesChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", filterInputRulesChain, "-j", "DROP")
	if err != nil {
		return err
	}

	err = ipt.Insert("filter", "INPUT", 1, "-i", devName, "-j", filterInputRulesChain)
	if err != nil {
		return err
	}

	return nil
}

func (f *Firewall) teardownIptables() {

	if f.closed {
		panic("something called teardown on an already torn down firewall instance")
	}

	log.Println("Removing Firewall rules...")

	var (
		err error
		ipt *iptables.IPTables
	)
	if config.Values.Wireguard.Range.IP.To4() != nil {
		ipt, err = iptables.New()
	} else {
		ipt, err = iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
	}

	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
		return
	}

	f.clearChains(ipt)

	log.Println("Firewall rules removed.")
}
