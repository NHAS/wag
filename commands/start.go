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
	"wag/router"
	"wag/webserver"
)

type start struct {
	fs *flag.FlagSet

	tunnelPort string
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
	fmt.Println("  Run the wag server on the settings found in config.json")
}

func (g *start) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	//Checks that the contents of the configuration file match reality and are sane

	if _, _, err := router.ServerDetails(); err != nil {
		return err
	}

	if len(config.Values().Issuer) == 0 {
		return errors.New("no issuer specified")
	}

	if len(config.Values().ExternalAddress) == 0 || net.ParseIP(config.Values().ExternalAddress) == nil {
		return errors.New("Invalid ExternalAddress: " + config.Values().ExternalAddress + " unable to parse as IP")

	}

	if config.Values().Lockout == 0 {
		return errors.New("lockout policy unconfigured")
	}

	if config.Values().SessionTimeoutMinutes == 0 {
		return errors.New("session timeout policy is not set")
	}

	err = database.Load(config.Values().DatabaseLocation, config.Values().Issuer, config.Values().Lockout)
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

	webserver.Start(error)

	err := router.Setup(error)
	if err != nil {
		return fmt.Errorf("unable to start router: %v", err)
	}
	defer router.TearDown()

	err = control.StartControlSocket()
	if err != nil {
		return fmt.Errorf("unable to create control socket: %v", err)
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
