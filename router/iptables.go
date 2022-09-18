package router

import (
	"fmt"
	"log"
	"net"
	"wag/config"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

func setupIptables() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	_, tunnelPort, err := net.SplitHostPort(config.Values().Webserver.Tunnel.ListenAddress)
	if err != nil {
		return fmt.Errorf("unable to split host port: %v", err)
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

	err = ipt.Append("filter", "INPUT", "-p", "icmp", "--icmp-type", "8", "-i", config.Values().WgDevName, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "DROP")
	if err != nil {
		return err
	}

	return nil
}

func TearDown() {
	_, tunnelPort, _ := net.SplitHostPort(config.Values().Webserver.Tunnel.ListenAddress)

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

	err = ipt.Delete("filter", "INPUT", "-p", "icmp", "--icmp-type", "8", "-i", config.Values().WgDevName, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "DROP")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	log.Println("Removing TC filters...")

	wgInterface, err := netlink.LinkByName(config.Values().WgDevName)
	if err != nil {
		log.Printf("cannot find %s: %v", config.Values().WgDevName, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: wgInterface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscDel(qdisc); err != nil {
		log.Printf("cannot remove clsact qdisc: %v", err)
	}
}
