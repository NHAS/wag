package firewall

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
	"wag/config"
	"wag/database"

	"github.com/coreos/go-iptables/iptables"
)

var (
	l          sync.RWMutex
	sessions   = map[string]string{}
	tunnelPort string
)

func Setup(tunnelWebserverPort string) error {

	tunnelPort = tunnelWebserverPort

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
	err = ipt.Append("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values().WgDevName, "--dport", tunnelWebserverPort, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "DROP")
	if err != nil {
		return err
	}

	err = setupXDP()
	if err != nil {
		return err
	}

	knownDevices, err := database.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range knownDevices {
		err := AddPublicRoutes(device.Address)
		if err != nil {
			return err
		}
	}

	log.Println("Started firewall management: \n",
		"\t\t\tSetting filter FORWARD policy to DROP\n",
		"\t\t\tAllowed input on tunnel port\n",
		"\t\t\tSet MASQUERADE\n",
		"\t\t\tXDP eBPF program managing firewall\n",
		"\t\t\tSet public forwards")

	return nil
}

func DeauthenticateOnEndpointChange(changedClient <-chan net.IP) {
	for ip := range changedClient {
		log.Println("Endpoint change, removing invalidating 2fa for: ", ip)
		if err := RemoveAuthorizedRoutes(ip.String()); err != nil {
			log.Println("Unable to remove forwards for device: ", err)
		}
	}
}

func AddPublicRoutes(address string) error {
	l.Lock()
	defer l.Unlock()

	device, err := database.GetDeviceByIP(address)
	if err != nil {
		return errors.New("user not found")
	}

	acls := config.Values().Acls.GetEffectiveAcl(device.Username)

	for _, publicAddress := range acls.Allow {

		k, err := ParseIP(publicAddress)
		if err != nil {
			return err
		}

		err = xdpAdd(net.ParseIP(device.Address), k)
		if err != nil {
			return err
		}
	}

	return nil
}

func AddAuthorizedRoutes(address, endpoint string) error {
	l.Lock()
	defer l.Unlock()
	device, err := database.GetDeviceByIP(address)
	if err != nil {
		return errors.New("user not found")
	}

	acls := config.Values().Acls.GetEffectiveAcl(device.Username)

	for _, route := range acls.Mfa {

		k, err := ParseIP(route)
		if err != nil {
			return err
		}

		err = xdpAdd(net.ParseIP(device.Address), k)
		if err != nil {
			return err
		}
	}

	sessions[address] = endpoint

	//Start a timer to remove entry
	go func(address, realendpoint string) {

		time.Sleep(time.Duration(config.Values().SessionTimeoutMinutes) * time.Minute)

		l.RLock()
		currentendpoint := sessions[address]
		l.RUnlock()

		if currentendpoint != realendpoint {
			return
		}

		log.Println(address, "expiring session because of timeout")
		if err := RemoveAuthorizedRoutes(address); err != nil {
			log.Println("Unable to remove forwards for device: ", err)
		}

	}(address, endpoint)

	return nil
}

func RemoveAuthorizedRoutes(address string) error {
	l.Lock()
	defer l.Unlock()

	delete(sessions, address)

	device, err := database.GetDeviceByIP(address)
	if err != nil {
		return errors.New("user not found")
	}

	acl := config.Values().Acls.GetEffectiveAcl(device.Username)

	for _, publicAddress := range acl.Mfa {

		k, err := ParseIP(publicAddress)
		if err != nil {
			return err
		}

		err = xdpRemoveEntry(net.ParseIP(device.Address), k)
		if err != nil {
			return err
		}
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

	xdpTearDown()
}
