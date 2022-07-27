package commands

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"wag/config"
	"wag/control"
	"wag/database"
	"wag/firewall"
	"wag/utils"
	"wag/webserver"
	"wag/wireguard_manager"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type start struct {
	fs *flag.FlagSet

	address    string
	tunnelPort string
	config     config.Config

	ctrl *wgctrl.Client
	dev  *wgtypes.Device
}

func Start() *start {
	gc := &start{
		fs: flag.NewFlagSet("start", flag.ContinueOnError),
	}

	return gc
}

func (g *start) Name() string {

	return g.fs.Name()
}

func (g *start) PrintUsage() {
	fmt.Println("Usage of start:")
	fmt.Println("  -config string")
	fmt.Println("    Configuration file location (default \"./config.json\")")
}

func (g *start) Init(args []string, c config.Config) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	g.config = c

	g.ctrl, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("Cannot start wireguard control %v", err)
	}

	g.dev, err = g.ctrl.Device(g.config.WgDevName)
	if err != nil {
		return fmt.Errorf("Unable to start wireguard-ctrl on device with name %s: %v", g.config.WgDevName, err)
	}

	i, err := net.InterfaceByName(g.config.WgDevName)
	if err != nil {
		return fmt.Errorf("Unable to get interface with name %s: %v", g.config.WgDevName, err)
	}

	addresses, err := i.Addrs()
	if err != nil {
		return fmt.Errorf("Unable to get address for interface %s: %v", g.config.WgDevName, err)
	}

	if len(addresses) < 1 {
		return errors.New("Wireguard interface does not have an ip address")
	}

	g.address = utils.GetIP(addresses[0].String())

	g.config.VPNServerAddress = net.ParseIP(utils.GetIP(addresses[0].String()))
	if err != nil {
		return errors.New("Unable to find server address from tunnel interface")
	}

	_, g.config.VPNRange, err = net.ParseCIDR(addresses[0].String())
	if err != nil {
		return errors.New("Unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
	}
	//Add the servers tunnel address to the captured addresses, otherwise clients cant connect to /authorise
	g.config.Routes.Public = append(g.config.Routes.Public, utils.GetIP(addresses[0].String())+"/32")

	if len(g.config.Issuer) == 0 {
		return errors.New("No issuer specified")
	}

	if len(g.config.ExternalAddress) == 0 || net.ParseIP(g.config.ExternalAddress) == nil {
		return errors.New("Invalid ExternalAddress: " + g.config.ExternalAddress + " unable to parse as IP")

	}

	if g.config.Lockout == 0 {
		return errors.New("Lockout policy unconfigured")
	}

	if g.config.SessionTimeoutMinutes == 0 {
		return errors.New("Session timeout policy is not set")
	}

	err = database.Load(g.config.DatabaseLocation, g.config.Issuer, g.config.Lockout)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	if g.config.Webserver.Tunnel.ListenAddress == "" {
		g.config.Webserver.Tunnel.ListenAddress = g.address + ":8080"
	}

	if g.config.Webserver.Public.ListenAddress == "" {
		g.config.Webserver.Public.ListenAddress = "0.0.0.0:8082"
	}

	_, g.tunnelPort, err = net.SplitHostPort(g.config.Webserver.Tunnel.ListenAddress)
	if err != nil {
		return fmt.Errorf("unable to split host port: %v", err)
	}

	if len(g.config.Routes.Public) == 0 && len(g.config.Routes.AuthRequired) == 0 {
		return fmt.Errorf("At least 1 route must be supplied")
	}

	if g.config.HelpMail == "" {
		return fmt.Errorf("No help email address specified")
	}

	return nil

}

func (g *start) Run() error {
	defer g.ctrl.Close()

	err := firewall.Setup(g.tunnelPort, g.config.WgDevName, g.config.Routes.Public, g.config.Routes.AuthRequired)
	if err != nil {
		return fmt.Errorf("Unable to initialise firewall: %v", err)
	}
	defer firewall.TearDown()

	endpointChanges := make(chan net.IP)

	error := make(chan error)

	webserver.Start(g.config, g.dev.PublicKey.String(), g.dev.ListenPort, error)

	go wireguard_manager.StartEndpointWatcher(g.config.WgDevName, g.config.VPNServerAddress, g.config.VPNRange, g.ctrl, endpointChanges, error)
	go firewall.BlockDeviceOnEndpointChange(endpointChanges)

	err = control.StartControlSocket()
	if err != nil {
		return fmt.Errorf("Unable to create control socket: %v", err)
	}
	defer control.TearDown()

	go func() {
		cancel := make(chan os.Signal, 1)
		signal.Notify(cancel, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

		<-cancel

		log.Println("\nGot ctrl + c gracefully exiting")

		error <- errors.New("ignore me I am control c")
	}()

	log.Println("Wag started successfully, Ctrl + C to stop")
	err = <-error
	if err != nil && !strings.Contains(err.Error(), "ignore me I am control c") {
		log.Println(err)
		return err
	}

	return nil
}
