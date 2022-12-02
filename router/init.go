package router

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"
	"github.com/coreos/go-iptables/iptables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func Setup(error chan<- error, iptables bool) (err error) {

	err = setupWireguard()
	if err != nil {
		return err
	}

	if iptables {
		err = setupIptables()
		if err != nil {
			return err
		}
	}

	defer func() {
		if err != nil {
			TearDown()
		}
	}()

	err = setupXDP()
	if err != nil {
		return err
	}

	go func() {
		startup := true
		for {

			dev, err := ctrl.Device(config.Values().Wireguard.DevName)
			if err != nil {
				error <- fmt.Errorf("endpoint watcher: %s", err)
				return
			}

			for _, p := range dev.Peers {

				if len(p.AllowedIPs) != 1 {
					log.Println("Warning, peer ", p.PublicKey.String(), " len(p.AllowedIPs) != 1, which is not supported")
					continue
				}

				ip := p.AllowedIPs[0].IP.String()

				d, err := data.GetDeviceByAddress(ip)
				if err != nil {
					log.Println("unable to get previous device endpoint for ", ip, err)
					if err := Deauthenticate(ip); err != nil {
						log.Println(ip, "unable to remove forwards for device: ", err)
					}
					continue
				}

				if d.Endpoint.String() != p.Endpoint.String() {

					err = data.UpdateDeviceEndpoint(p.AllowedIPs[0].IP.String(), p.Endpoint)
					if err != nil {
						log.Println(ip, "unable to update device endpoint: ", err)
					}

					//Dont try and remove rules, if we've just started
					if !startup {
						log.Println(ip, "endpoint changed", d.Endpoint.String(), "->", p.Endpoint.String())
						if err := Deauthenticate(ip); err != nil {
							log.Println(ip, "unable to remove forwards for device: ", err)
						}
					}
				}

			}

			startup = false

			time.Sleep(100 * time.Millisecond)
		}
	}()

	log.Println("Started firewall management: \n",
		"\t\t\tSetting filter FORWARD policy to DROP\n",
		"\t\t\tAllowed input on tunnel port\n",
		"\t\t\tSet MASQUERADE\n",
		"\t\t\tXDP eBPF program managing firewall\n",
		"\t\t\tSet public forwards")

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
	err = ipt.Delete("filter", "FORWARD", "-i", config.Values().Wireguard.DevName, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("nat", "POSTROUTING", "-s", config.Values().Wireguard.Range.String(), "-j", "MASQUERADE")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	//Allow input to authorize web server on the tunnel
	err = ipt.Delete("filter", "INPUT", "-m", "tcp", "-p", "tcp", "-i", config.Values().Wireguard.DevName, "--dport", tunnelPort, "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-p", "icmp", "--icmp-type", "8", "-i", config.Values().Wireguard.DevName, "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Append("filter", "INPUT", "-i", config.Values().Wireguard.DevName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	err = ipt.Delete("filter", "INPUT", "-i", config.Values().Wireguard.DevName, "-j", "DROP")
	if err != nil {
		log.Println("Unable to clean up firewall rules: ", err)
	}

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Println("Unable to remove wireguard device, netlink connection failed: ", err.Error())
		return
	}
	defer conn.Close()

	err = delWg(conn, config.Values().Wireguard.DevName)
	if err != nil {
		log.Println("Unable to remove wireguard device, delete failed: ", err.Error())
		return
	}

}
