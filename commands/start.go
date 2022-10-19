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

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/database"
	"github.com/NHAS/wag/router"
	"github.com/NHAS/wag/webserver"
)

type start struct {
	fs         *flag.FlagSet
	config     string
	noIptables bool
}

func Start() *start {
	gc := &start{
		fs: flag.NewFlagSet("start", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")
	gc.fs.Bool("noiptables", false, "Do not add iptables rules")

	return gc
}

func (g *start) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *start) Name() string {

	return g.fs.Name()
}

func (g *start) PrintUsage() {
	fmt.Println("Usage of start:")
	fmt.Println("  Start wag server (does not daemonise)")
	g.fs.PrintDefaults()
}

func (g *start) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "noiptables":
			g.noIptables = false
		}
	})

	err := config.Load(g.config)
	if err != nil {
		return err
	}

	if len(config.Values().Issuer) == 0 {
		return errors.New("no issuer specified")
	}

	if len(config.Values().ExternalAddress) == 0 {
		return errors.New("Invalid ExternalAddress is empty")
	}

	if net.ParseIP(config.Values().ExternalAddress) == nil {

		addresses, err := net.LookupIP(config.Values().ExternalAddress)
		if err != nil {
			return errors.New("Invalid ExternalAddress: " + config.Values().ExternalAddress + " unable to parse as IP")
		}

		if len(addresses) == 0 {
			return errors.New("Invalid ExternalAddress: " + config.Values().ExternalAddress + " not IPv4 or IPv6 external addresses found")
		}
	}

	if config.Values().Lockout == 0 {
		return errors.New("lockout policy unconfigured")
	}

	if config.Values().MaxSessionLifetimeMinutes == 0 {
		return errors.New("session max lifetime policy is not set (may be disabled by setting it to -1)")
	}

	if config.Values().SessionInactivityTimeoutMinutes == 0 {
		return errors.New("session inactivity timeout policy is not set (may be disabled by setting it to -1)")
	}

	err = database.Load(config.Values().DatabaseLocation)
	if err != nil {
		return fmt.Errorf("cannot load database: %v", err)
	}

	if config.Values().Webserver.Tunnel.ListenAddress == "" {
		return fmt.Errorf("tunnel listen address is not set (Tunnel.ListenAddress)")
	}

	if config.Values().Webserver.Public.ListenAddress == "" {
		return fmt.Errorf("public listen address is not set (Public.ListenAddress)")
	}

	if config.Values().HelpMail == "" {
		return fmt.Errorf("no help email address specified")
	}

	return nil

}

func (g *start) Run() error {

	error := make(chan error)

	if _, err := os.Stat(wag_was_upgraded); err == nil {
		os.Remove(wag_was_upgraded)
		g.noIptables = true
		log.Println("Wag was upgraded to", config.Version, " iptables will not be configured. (Due to presence of", wag_was_upgraded, ")")
	}

	err := router.Setup(error, !g.noIptables)
	if err != nil {
		return fmt.Errorf("unable to start router: %v", err)
	}
	defer router.TearDown()

	err = control.StartControlSocket()
	if err != nil {
		return fmt.Errorf("unable to create control socket: %v", err)
	}
	defer control.TearDown()

	webserver.Start(error)

	go func() {
		cancel := make(chan os.Signal, 1)
		signal.Notify(cancel, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE, os.Interrupt, syscall.SIGQUIT)

		<-cancel

		log.Println("\nGot signal gracefully exiting")

		error <- errors.New("ignore me I am signal")
	}()

	log.Println("Wag started successfully, Ctrl + C to stop")
	err = <-error
	if err != nil && !strings.Contains(err.Error(), "ignore me I am signal") {
		return err
	}

	return nil
}
