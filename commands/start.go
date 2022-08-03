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
	"wag/webserver"
	"wag/wireguard_manager"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type start struct {
	fs *flag.FlagSet

	tunnelPort string

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

func (g *start) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	g.ctrl, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("Cannot start wireguard control %v", err)
	}

	g.dev, err = g.ctrl.Device(config.Values().WgDevName)
	if err != nil {
		return fmt.Errorf("Unable to start wireguard-ctrl on device with name %s: %v", config.Values().WgDevName, err)
	}

	if len(config.Values().Issuer) == 0 {
		return errors.New("No issuer specified")
	}

	if len(config.Values().ExternalAddress) == 0 || net.ParseIP(config.Values().ExternalAddress) == nil {
		return errors.New("Invalid ExternalAddress: " + config.Values().ExternalAddress + " unable to parse as IP")

	}

	if config.Values().Lockout == 0 {
		return errors.New("Lockout policy unconfigured")
	}

	if config.Values().SessionTimeoutMinutes == 0 {
		return errors.New("Session timeout policy is not set")
	}

	err = database.Load(config.Values().DatabaseLocation, config.Values().Issuer, config.Values().Lockout)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	if config.Values().Webserver.Tunnel.ListenAddress == "" {
		return fmt.Errorf("Tunnel listen address is not set (Tunnel.ListenAddress)")
	}

	if config.Values().Webserver.Public.ListenAddress == "" {
		return fmt.Errorf("The public listen address is not set (Public.ListenAddress)")
	}

	_, g.tunnelPort, err = net.SplitHostPort(config.Values().Webserver.Tunnel.ListenAddress)
	if err != nil {
		return fmt.Errorf("unable to split host port: %v", err)
	}

	if config.Values().HelpMail == "" {
		return fmt.Errorf("No help email address specified")
	}

	return nil

}

func (g *start) Run() error {
	defer g.ctrl.Close()

	err := firewall.Setup(g.tunnelPort)
	if err != nil {
		return fmt.Errorf("Unable to initialise firewall: %v", err)
	}
	defer firewall.TearDown()

	endpointChanges := make(chan net.IP)

	error := make(chan error)

	webserver.Start(g.dev.PublicKey.String(), g.dev.ListenPort, error)

	go wireguard_manager.StartEndpointWatcher(config.Values().WgDevName, config.Values().VPNServerAddress, config.Values().VPNRange, g.ctrl, endpointChanges, error)
	go firewall.DeauthenticateOnEndpointChange(endpointChanges)

	err = control.StartControlSocket()
	if err != nil {
		return fmt.Errorf("Unable to create control socket: %v", err)
	}
	defer control.TearDown()

	go func() {
		cancel := make(chan os.Signal, 1)
		signal.Notify(cancel, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE, os.Interrupt, syscall.SIGQUIT)

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
