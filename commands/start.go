package commands

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/webserver"
	"github.com/NHAS/wag/pkg/control/server"
	"github.com/NHAS/wag/ui"
	"golang.org/x/sys/unix"
)

type start struct {
	fs               *flag.FlagSet
	config           string
	clusterJoinToken string
	noIptables       bool
}

func Start() *start {
	gc := &start{
		fs: flag.NewFlagSet("start", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.clusterJoinToken, "join", "", "Cluster join token")
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
			g.noIptables = true
		}
	})

	// Taken from: https://github.com/cilium/ebpf/blob/9444f0c545e0bda2f3db40bdaf69381df9f51af4/internal/version.go
	var uname unix.Utsname
	err := unix.Uname(&uname)
	if err != nil {
		return errors.New("could not get kernel version: " + err.Error())
	}

	kernelVersion := unix.ByteSliceToString(uname.Release[:])

	var major, minor, patch uint16
	n, _ := fmt.Sscanf(kernelVersion, "%d.%d.%d", &major, &minor, &patch)
	if n < 2 {
		return errors.New("this kernel version did not conform to kernel version format: " + kernelVersion)
	}

	if major < 5 || major == 5 && minor < 9 {
		return errors.New("kernel is too old(" + kernelVersion + "), wag requires kernel version > 5.9")
	}

	if g.clusterJoinToken == "" {
		err = config.Load(g.config)
		if err != nil {
			return err
		}
	}

	err = data.Load(config.Values.DatabaseLocation, g.clusterJoinToken, false)
	if err != nil {
		return fmt.Errorf("cannot load database: %v", err)
	}

	return nil

}

func (g *start) Run() error {

	var err error
	defer func() {
		data.TearDown()
	}()

	errorChan := make(chan error)

	if !config.Values.Clustering.Witness {

		err = router.Setup(errorChan, !g.noIptables)
		if err != nil {
			return fmt.Errorf("unable to start router: %v", err)
		}
		defer func() {
			if !(strings.Contains(err.Error(), "listen unix") && strings.Contains(err.Error(), "address already in use")) {
				router.TearDown(false)
			}
		}()

		err = server.StartControlSocket()
		if err != nil {
			return fmt.Errorf("unable to create control socket: %v", err)
		}
		defer func() {

			if !(strings.Contains(err.Error(), "listen unix") && strings.Contains(err.Error(), "address already in use")) {
				server.TearDown()
			}
		}()

		err = webserver.Start(errorChan)
		if err != nil {
			return fmt.Errorf("unable to start webserver: %v", err)
		}

		err = ui.StartWebServer(errorChan)
		if err != nil {
			return fmt.Errorf("unable to start management web server: %v", err)
		}
	}

	go func() {
		cancel := make(chan os.Signal, 1)
		signal.Notify(cancel, syscall.SIGTERM, syscall.SIGINT, os.Interrupt, syscall.SIGQUIT)

		s := <-cancel
		go func(chan os.Signal) {
			<-cancel
			log.Println("got force quit, killing without exiting nicely")
			os.Exit(1)
		}(cancel)

		log.Printf("Got signal %s gracefully exiting\n", s)

		errorChan <- errors.New("ignore me I am signal")
	}()

	wagType := "Wag"
	if config.Values.Clustering.Witness {
		wagType = "Witness Node"
	}

	log.Printf("%s started successfully, Ctrl + C to stop", wagType)

	err = <-errorChan
	if err != nil && !strings.Contains(err.Error(), "ignore me I am signal") {
		return err
	}

	return nil
}
