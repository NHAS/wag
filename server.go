package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	Ctrl  *wgctrl.Client
	WgDev *wgtypes.Device
)

type server struct {
	fs *flag.FlagSet

	config  string
	address string
}

func ServerSubCommand() *server {
	gc := &server{
		fs: flag.NewFlagSet("server", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")

	return gc
}

func (g *server) Name() string {

	return g.fs.Name()
}

func (g *server) PrintUsage() {

	g.fs.Usage()
}

func (g *server) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	err = LoadConfig(g.config)
	if err != nil {
		return err
	}

	Ctrl, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("Cannot start wireguard control %v", err)
	}

	WgDev, err = Ctrl.Device(Config.WgDevName)
	if err != nil {
		return fmt.Errorf("Unable to start wireguard-ctrl on device with name %s: %v", Config.WgDevName, err)
	}

	i, err := net.InterfaceByName(Config.WgDevName)
	if err != nil {
		return fmt.Errorf("Unable to get interface with name %s: %v", Config.WgDevName, err)
	}

	addresses, err := i.Addrs()
	if err != nil {
		return fmt.Errorf("Unable to get address for interface %s: %v", Config.WgDevName, err)
	}

	if len(addresses) < 1 {
		return errors.New("Wireguard interface does not have an ip address")
	}

	g.address = GetIP(addresses[0].String())

	_, Config.VPNRange, err = net.ParseCIDR(addresses[0].String())
	if err != nil {
		return errors.New("Unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
	}
	//Add the servers tunnel address to the captured addresses, otherwise clients cant connect to /authorise
	Config.CapturedAddreses = append(Config.CapturedAddreses, GetIP(addresses[0].String())+"/32")

	if len(Config.Issuer) == 0 {
		return errors.New("No issuer specified")
	}

	if len(Config.ExternalAddress) == 0 || net.ParseIP(Config.ExternalAddress) == nil {
		return errors.New("Invalid ExternalAddress: " + Config.ExternalAddress + " unable to parse as IP")

	}

	err = LoadDb(Config.DatabaseLocation)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	return nil

}

func (g *server) Run() error {
	defer Ctrl.Close()

	log.Println("Started listening: ")

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/", index)

	error := make(chan error)

	go func() {

		if Config.Listen.Tunnel == "" {
			Config.Listen.Tunnel = g.address + ":8080"
		}

		log.Println("\tTunnel Listener: ", Config.Listen.Tunnel)
		error <- http.ListenAndServe(Config.Listen.Tunnel, tunnel)
	}()

	public := http.NewServeMux()
	public.HandleFunc("/register_device", registerDevice)

	go func() {

		if Config.Listen.Public == "" {
			Config.Listen.Public = "0.0.0.0:8082"
		}

		log.Println("\tPublic Listener: ", Config.Listen.Public)
		error <- http.ListenAndServe(Config.Listen.Public, public)
	}()

	err := SetupFirewall()
	if err != nil {
		return fmt.Errorf("Unable to initialise firewall: %v", err)
	}
	defer TearDownFirewall()

	endpointChanges := make(chan net.IP)

	go func() {
		error <- fmt.Errorf("Wireguard endpoint watcher failed: %v", WireguardEndpointWatcher(Ctrl, endpointChanges))
	}()

	go RemoveForwardsOnEndpointChange(endpointChanges)

	go func() {
		cancel := make(chan os.Signal, 1)
		signal.Notify(cancel, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

		<-cancel

		log.Println("\nGot ctrl + c gracefully exiting")

		error <- errors.New("ignore me I am control c")
	}()

	err = <-error
	if err != nil && !strings.Contains(err.Error(), "ignore me I am control c") {
		log.Println(err)
		return err
	}

	return nil
}
