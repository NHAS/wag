package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"wag/config"
	"wag/database"

	"github.com/coreos/go-iptables/iptables"
)

var (
	l        sync.RWMutex
	sessions = map[string]string{}
)

func Setup(tunnelWebserverPort string) error {

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.ChangePolicy("filter", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	//Make our custom chains so we can delete it when we finish up
	err = ipt.NewChain("filter", "WAG_FORWARD")
	if err != nil {
		return err
	}

	err = ipt.NewChain("filter", "WAG_INPUT")
	if err != nil {
		return err
	}

	err = ipt.NewChain("nat", "WAG_POSTROUTING")
	if err != nil {
		return err
	}

	//Setup the links to the new chains
	err = ipt.Append("filter", "FORWARD", "-i", config.Values().WgDevName, "-j", "WAG_FORWARD")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "WAG_INPUT")
	if err != nil {
		return err
	}

	err = ipt.Append("nat", "POSTROUTING", "-s", config.Values().VPNRange.String(), "-j", "WAG_POSTROUTING")
	if err != nil {
		return err
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Append("filter", "WAG_INPUT", "-m", "tcp", "-p", "tcp", "--dport", tunnelWebserverPort, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "WAG_INPUT", "-j", "DROP")
	if err != nil {
		return err
	}

	err = RefreshPublicRoutes()
	if err != nil {
		return err
	}

	log.Println("Started firewall management: \n",
		"\t\t\tSetting filter FORWARD policy to DROP\n",
		"\t\t\tCreated WAG_INPUT chain\n",
		"\t\t\tCreated WAG_FORWARD chain\n",
		"\t\t\tCreated WAG_POSTROUTING chain\n",
		"\t\t\tSet public forwards")

	return nil
}

func RefreshPublicRoutes() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	devices, err := database.GetDevices()
	if err != nil {
		return err
	}

	err = ipt.ClearChain("nat", "WAG_POSTROUTING")
	if err != nil {
		return err
	}

	for _, device := range devices {

		acl, ok := config.Values().Acls.GetEffectiveAcl(device.Username)
		if !ok {
			log.Println("Warning, no acl defined for", device.Username)
			continue
		}

		err = ipt.Append("nat", "WAG_POSTROUTING", "-d", strings.Join(append(acl.Mfa, acl.Allow...), ","), "-j", "MASQUERADE")
		if err != nil {
			return err
		}

		err = ipt.ClearChain("filter", "WAG_FORWARD")
		if err != nil {
			return err
		}

		//Add public routes
		err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Allow, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if err != nil {
			return err
		}

		err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Allow, ","), "-j", "ACCEPT")
		if err != nil {
			return err
		}

		l.RLock()

		if _, ok := sessions[device.Address]; ok {
			//Add mfa routes, if there is still an active session
			err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Mfa, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
			if err != nil {
				return err
			}

			err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Mfa, ","), "-j", "ACCEPT")
			if err != nil {
				return err
			}
		}

		l.RUnlock()

	}

	return nil
}

func BlockDeviceOnEndpointChange(changedClient <-chan net.IP) {
	for ip := range changedClient {
		log.Println("Endpoint change, removing invalidating 2fa for: ", ip)
		if err := Block(ip.String()); err != nil {
			log.Println("Unable to remove forwards for device: ", err)
		}
	}
}

func Allow(address, endpoint string, expire time.Duration) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	device, err := database.GetDeviceByIP(address)
	if err != nil {
		return errors.New("User not found")
	}

	acls, ok := config.Values().Acls.GetEffectiveAcl(device.Username)
	if !ok {
		return errors.New("No acl defined for user: " + device.Username)
	}

	//Add mfa routes
	err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acls.Mfa, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acls.Mfa, ","), "-j", "ACCEPT")
	if err != nil {
		return err
	}

	l.Lock()
	// Removed in block
	sessions[address] = endpoint

	l.Unlock()

	//Start a timer to remove entry
	go func(address, realendpoint string) {
		select {
		case <-time.After(expire):

			l.RLock()
			currentendpoint := sessions[address]
			l.RUnlock()

			if currentendpoint != realendpoint {
				return
			}

			log.Println(address, "expiring session because of timeout")
			if err := Block(address); err != nil {
				log.Println("Unable to remove forwards for device: ", err)
			}
			return
		}
	}(address, endpoint)

	return nil
}

func GetAllAllowed() map[string]string {
	l.RLock()
	defer l.RUnlock()
	output := map[string]string{}
	for device, endpoint := range sessions {
		output[device] = endpoint
	}
	return output
}

func IsAlreadyAuthed(address string) string {
	l.RLock()
	output := sessions[address]
	l.RUnlock()
	return output
}

func Block(address string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	device, err := database.GetDeviceByIP(address)
	if err != nil {
		return errors.New("User not found")
	}

	acl, ok := config.Values().Acls.GetEffectiveAcl(device.Username)
	if !ok {
		return errors.New("No acl defined for user: " + device.Username)
	}

	//Add mfa routes
	err1 := ipt.Delete("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Mfa, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err2 := ipt.Delete("filter", "WAG_FORWARD", "-s", device.Address, "-d", strings.Join(acl.Mfa, ","), "-j", "ACCEPT")
	if err != nil {
		return err
	}

	//Make sure we try to do both opertations
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%v:%v", err1, err2)
	}

	l.Lock()

	delete(sessions, address)

	l.Unlock()

	return nil
}

func TearDown() {
	log.Println("Removing Firewall rules...")

	ipt, err := iptables.New()
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
		return
	}

	//Remove link to custom chains
	err = ipt.Delete("nat", "POSTROUTING", "-s", config.Values().VPNRange.String(), "-j", "WAG_POSTROUTING")
	if err != nil {
		log.Println("Unable to clean up postrouting WAG_POSTROUTING rule: ", err)
	}

	err = ipt.Delete("filter", "FORWARD", "-i", config.Values().WgDevName, "-j", "WAG_FORWARD")
	if err != nil {
		log.Println("Unable to clean up forward WAG_FORWARD rule: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values().WgDevName, "-j", "WAG_INPUT")
	if err != nil {
		log.Println("Unable to clean up input WAG_INPUT rule: ", err)
	}

	// Delete the chains themselves
	err = ipt.ClearAndDeleteChain("nat", "WAG_POSTROUTING")
	if err != nil {
		log.Println("Unable to clean up WAG_POSTROUTING chain: ", err)
	}

	err = ipt.ClearAndDeleteChain("filter", "WAG_FORWARD")
	if err != nil {
		log.Println("Unable to clean up WAG_FORWARD chain: ", err)
	}

	err = ipt.ClearAndDeleteChain("filter", "WAG_INPUT")
	if err != nil {
		log.Println("Unable to clean up WAG_INPUT chain: ", err)
	}
}
