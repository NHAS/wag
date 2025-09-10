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

	"github.com/NHAS/wag/adminui"
	"github.com/NHAS/wag/debug"
	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/mfaportal"
	"github.com/NHAS/wag/internal/publicwebserver"

	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control/server"
)

type start struct {
	fs               *flag.FlagSet
	Config           string
	clusterJoinToken string
	NoIptables       bool

	DB interfaces.Database
}

func Start() *start {
	gc := &start{
		fs: flag.NewFlagSet("start", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.clusterJoinToken, "join", "", "Cluster join token")
	gc.fs.StringVar(&gc.Config, "config", "./config.json", "Configuration file location")

	gc.fs.BoolVar(&gc.NoIptables, "noiptables", false, "Do not add iptables rules")

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
			g.NoIptables = true
		}
	})

	if g.clusterJoinToken == "" {
		err := config.Load(g.Config)
		if err != nil {
			return err
		}
	}

	var err error
	g.DB, err = data.Load(g.clusterJoinToken, false)
	if err != nil {
		return fmt.Errorf("cannot load database: %w", err)
	}

	err = autotls.Initialise(g.DB)
	if err != nil {
		return fmt.Errorf("failed to initialise auto tls module: %w", err)
	}
	return nil

}

func startWag(db interfaces.Database, noIptables bool, cancel <-chan bool, complete chan<- bool, errorChan chan<- error) func(string) {

	// Make sure that node states are sync'd
	var (
		lck       sync.Mutex
		wasDead   bool = true
		cancelled bool
		lastState string

		routerFw *router.Firewall

		controlServer   *server.WagControlSocketServer
		mfaPortal       *mfaportal.MfaPortal
		enrolmentServer *publicwebserver.PublicWebserver
		adminUI         *adminui.AdminUI

		err error
	)

	teardown := func() {
		// Guarded by lck

		if controlServer != nil {
			// Tear down Unix socket
			controlServer.TearDown()
		}

		if mfaPortal != nil {
			mfaPortal.Close()
		}

		if enrolmentServer != nil {
			enrolmentServer.Close()
		}

		if adminUI != nil {
			adminUI.Close()
		}

		if routerFw != nil {
			routerFw.Close()
		}
	}

	go func() {
		<-cancel
		lck.Lock()
		defer lck.Unlock()
		cancelled = true
		teardown()

		complete <- true
	}()

	return func(stateText string) {
		lck.Lock()
		defer lck.Unlock()

		if cancelled {
			return
		}

		if lastState != stateText {
			log.Println("node entered state: ", stateText)
			lastState = stateText
		}

		switch stateText {
		case "dead":
			if !wasDead {

				if !config.Values.Clustering.Witness {
					log.Println("Tearing down node")
					teardown()
					log.Println("Tear down complete")
				} else {
					log.Println("refusing to tear down witness node (nothing to tear down)")
				}

				// Only teardown if we were at one point alive
				wasDead = true
			}
		case "healthy":
			if wasDead {

				if !config.Values.Clustering.Witness {
					routerFw, err = router.New(db, !noIptables)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start router: %v", err)
						return
					}

					controlServer, err = server.NewControlServer(db, routerFw)
					if err != nil {
						errorChan <- fmt.Errorf("unable to create control socket: %v", err)
						return
					}

					mfaPortal, err = mfaportal.New(db, routerFw, errorChan)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start mfa portal: %v", err)
						return
					}

					enrolmentServer, err = publicwebserver.New(db, routerFw, errorChan)
					if err != nil {
						errorChan <- fmt.Errorf("unable to start enrolment server: %v", err)
						return
					}

					if config.Values.Webserver.Management.Enabled {
						adminUI, err = adminui.New(db, routerFw, errorChan)
						if err != nil {
							errorChan <- fmt.Errorf("unable to start management web server: %v", err)
							return
						}
					}
				}

				if db.ClusterManagementEnabled() {
					if !db.IsCurrentNodeLearner() {
						err := db.SetWitness(config.Values.Clustering.Witness)
						if err != nil {
							errorChan <- fmt.Errorf("to write witness data when cluster is healthy: %v", err)
							return
						}

						err = db.SetCurrentNodeVersion()
						if err != nil {
							errorChan <- fmt.Errorf("to write version data when cluster is healthy: %v", err)
							return
						}

					}
				}

				wasDead = false
			}
		}
	}
}

func (g *start) Run() error {

	var err error
	defer g.DB.TearDown()

	errorChan := make(chan error)
	cancel := make(chan bool)
	complete := make(chan bool)

	_, err = g.DB.RegisterClusterHealthListener(startWag(g.DB, g.NoIptables, cancel, complete, errorChan))
	if err != nil {
		return err
	}

	wagType := "Wag"

	if g.DB.ClusterManagementEnabled() {
		if config.Values.Clustering.Witness {
			wagType = "Witness Node"
		}

		if g.DB.IsCurrentNodeLearner() {
			wagType += " Learner"
		}

		if config.Values.Clustering.Witness {
			log.Println("this node is a witness, and will not start a wireguard device")
		}

		if g.DB.IsCurrentNodeLearner() {
			log.Println("Node has successfully joined cluster! This node is currently a learner, and needs to be promoted in the UI before wireguard device will start")
		}
	} else {
		wagType += " (remote cluster)"
	}

	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT, os.Interrupt, syscall.SIGQUIT)

		s := <-signalChan
		go func(chan os.Signal) {
			<-signalChan
			log.Println("got force quit, killing without exiting nicely")
			os.Exit(1)
		}(signalChan)

		errorChan <- errors.New("ignore me I am signal")

		log.Printf("Got signal %s gracefully exiting\n", s)

	}()

	log.Printf("%s (%s) starting, Ctrl + C to stop", wagType, config.Version)

	if config.Values.DevMode {
		debug.StartPprof()
	}

	err = <-errorChan
	cancel <- true

	<-complete

	if err != nil && !strings.Contains(err.Error(), "ignore me I am signal") {
		return err
	}

	return nil
}
