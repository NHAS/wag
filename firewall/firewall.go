package firewall

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

var (
	l        sync.RWMutex
	sessions = map[string]string{}

	//List of addresses that a client is able to hit through the tunnel at all times
	public []string

	//Routes that require the client to be authed
	authed []string

	wgDevName string
)

func Setup(tunnelWebserverPort, devName string, unauthedAddrs, authedAddrs []string) error {

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	public = unauthedAddrs
	authed = authedAddrs
	wgDevName = devName

	err = ipt.ChangePolicy("filter", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	err = ipt.Append("nat", "POSTROUTING", "-d", strings.Join(append(public, authed...), ","), "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	//Make our custom chain so we can delete it when we finish up
	err = ipt.NewChain("filter", "WAG_FORWARD")
	if err != nil {
		return err
	}

	err = ipt.NewChain("filter", "WAG_INPUT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "FORWARD", "-i", wgDevName, "-j", "WAG_FORWARD")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "INPUT", "-i", wgDevName, "-j", "WAG_INPUT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "WAG_FORWARD", "-d", strings.Join(public, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	//Allow access to any addresses that are not MFA by default
	err = ipt.Append("filter", "WAG_FORWARD", "-d", strings.Join(public, ","), "-j", "ACCEPT")
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

	log.Println("Started firewall management: \n",
		"\t\t\tSetting filter FORWARD policy to DROP\n",
		"\t\t\tCreated WAG_INPUT chain\n",
		"\t\t\tCreated WAG_FORWARD chain\n",
		"\t\t\tSet public forwards")

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

func Allow(address string, expire time.Duration) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "WAG_FORWARD", "-s", address, "-d", strings.Join(authed, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	err = ipt.Append("filter", "WAG_FORWARD", "-s", address, "-d", strings.Join(authed, ","), "-j", "ACCEPT")
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

func GetAllowedEndpoint(address string) string {
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

	l.Lock()

	delete(sessions, address)

	l.Unlock()

	err1 := ipt.Delete("filter", "WAG_FORWARD", "-s", address, "-d", strings.Join(authed, ","), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	err2 := ipt.Delete("filter", "WAG_FORWARD", "-s", address, "-d", strings.Join(authed, ","), "-j", "ACCEPT")

	//Make sure we try to do both opertations
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%v:%v", err1, err2)
	}

	return nil
}

func TearDown() {
	log.Println("Removing Firewall rules...")

	ipt, err := iptables.New()
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
		return
	}

	err = ipt.Delete("nat", "POSTROUTING", "-d", strings.Join(append(public, authed...), ","), "-j", "MASQUERADE")
	if err != nil {
		log.Println("Unable to clean up nat POSTROUTING rule: ", err)
	}

	err = ipt.Delete("filter", "FORWARD", "-i", wgDevName, "-j", "WAG_FORWARD")
	if err != nil {
		log.Println("Unable to clean up forward WAG_FORWARD rule: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", wgDevName, "-j", "WAG_INPUT")
	if err != nil {
		log.Println("Unable to clean up input WAG_INPUT rule: ", err)
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
