package commands

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
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

func teardown() {
	router.TearDown(false)
	// Tear down Unix socket
	server.TearDown()

}

func clusterState(noIptables bool, errorChan chan<- error) func(string) {

	// Make sure that node states are sync'd
	var lck sync.Mutex
	wasDead := true
	lastState := ""
	return func(stateText string) {
		lck.Lock()
		defer lck.Unlock()

		if lastState != stateText {
			log.Println("node entered state: ", stateText)
			lastState = stateText
		}

		switch stateText {
		case "dead":
			if !wasDead {
				log.Println("Tearing down node")

				teardown()

				log.Println("Tear down complete")

				// Only teardown if we were at one point alive
				wasDead = true
			}
		case "healthy":
			if wasDead {

				if !config.Values.Clustering.Witness {
					err := router.Setup(errorChan, !noIptables)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start router: %v", err)
						return
					}

					err = server.StartControlSocket()
					if err != nil {
						errorChan <- fmt.Errorf("unable to create control socket: %v", err)
						return
					}

					err = webserver.Start(errorChan)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start webserver: %v", err)
						return
					}

					err = ui.StartWebServer(errorChan)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start management web server: %v", err)
						return
					}
				}

				wasDead = false
			}
		}
	}
}

func (g *start) Run() error {

	var err error
	defer data.TearDown()

	errorChan := make(chan error)

	_, err = data.RegisterClusterHealthListener(clusterState(g.noIptables, errorChan))
	if err != nil {
		return err
	}

	if config.Values.Clustering.Witness {
		log.Println("this node is a witness, and will not start a wireguard device")
	}

	if data.IsLearner() {
		log.Println("Node has successfully joined cluster! This node is currently a learner, and needs to be promoted in the UI before wireguard device will start")
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

		errorChan <- errors.New("ignore me I am signal")

		log.Printf("Got signal %s gracefully exiting\n", s)

	}()

	wagType := "Wag"
	if config.Values.Clustering.Witness {
		wagType = "Witness Node"
	}

	if data.IsLearner() {
		wagType += " Learner"
	}

	log.Printf("%s starting, Ctrl + C to stop", wagType)

	err = <-errorChan
	teardown()
	if err != nil && !strings.Contains(err.Error(), "ignore me I am signal") {
		return err
	}

	return nil
}
