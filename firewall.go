package main

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

func SetupFirewall() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	log.Println("Setting filter FORWARD policy to DROP")
	err = ipt.ChangePolicy("filter", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	err = ipt.Append("nat", "POSTROUTING", "-d", strings.Join(append(Config.CapturedAddreses, Config.MFAAddresses...), ","), "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	_, port, err := net.SplitHostPort(Config.Listen.Tunnel)
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-i", Config.WgDevName, "-d", strings.Join(Config.CapturedAddreses, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	//Allow access to any addresses that are not MFA by default
	err = ipt.Append("filter", "FORWARD", "-i", Config.WgDevName, "-d", strings.Join(Config.CapturedAddreses, ","), "-j", "ACCEPT")
	if err != nil {
		return err
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Append("filter", "INPUT", "-i", Config.WgDevName, "-m", "tcp", "-p", "tcp", "--dport", port, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", Config.WgDevName, "-j", "DROP")
	if err != nil {
		return err
	}

	return nil
}

func RemoveForwardsOnEndpointChange(changedClient <-chan net.IP) {
	for ip := range changedClient {
		log.Println("NOT IMPLEMENTED 'REMOVING'", ip, DisallowDevice(ip.String()))
	}
}

func AllowDevice(address string, expire time.Duration) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-s", address, "-d", strings.Join(Config.MFAAddresses, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-s", address, "-d", strings.Join(Config.MFAAddresses, ","), "-j", "ACCEPT")
	if err != nil {
		return err
	}

	//Start a timer to remove entry
	go func() {
		time.Sleep(expire)
		DisallowDevice(address)
	}()

	return nil
}

func DisallowDevice(address string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.Delete("filter", "FORWARD", "-s", address, "-d", strings.Join(Config.MFAAddresses, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Delete("filter", "FORWARD", "-s", address, "-d", strings.Join(Config.MFAAddresses, ","), "-j", "ACCEPT")
	if err != nil {
		return err
	}

	return nil
}

func TearDownFirewall() {
	log.Println("Removing Firewall rules...")
	ipt, _ := iptables.New()
	ipt.Delete("nat", "POSTROUTING", "-d", strings.Join(append(Config.CapturedAddreses, Config.MFAAddresses...), ","), "-j", "MASQUERADE")

	_, port, _ := net.SplitHostPort(Config.Listen.Tunnel)

	ipt.Delete("filter", "INPUT", "-i", Config.WgDevName, "-m", "tcp", "-p", "tcp", "--dport", port, "-j", "ACCEPT")

	ipt.Delete("filter", "INPUT", "-i", Config.WgDevName, "-j", "DROP")

	ipt.Delete("filter", "FORWARD", "-i", Config.WgDevName, "-d", strings.Join(Config.CapturedAddreses, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	ipt.Delete("filter", "FORWARD", "-i", Config.WgDevName, "-d", strings.Join(Config.CapturedAddreses, ","), "-j", "ACCEPT")
}
