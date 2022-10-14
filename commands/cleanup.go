package commands

import (
	"flag"
	"fmt"
	"os"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/router"
)

type cleanup struct {
	fs     *flag.FlagSet
	config string
	force  bool
}

func Cleanup() *cleanup {
	gc := &cleanup{
		fs: flag.NewFlagSet("cleanup", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")
	gc.fs.Bool("force", false, "Ignore /tmp/wag-no-cleanup and remove all iptables rules and other wag changes")

	return gc
}

func (g *cleanup) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *cleanup) Name() string {

	return g.fs.Name()
}

func (g *cleanup) PrintUsage() {
	fmt.Println("Usage of cleanup:")
	fmt.Println("  Attempt to clear all iptables rules that wag creates, and bring down wireguard interface")
	g.fs.PrintDefaults()
}

func (g *cleanup) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "force":
			g.force = true
		}
	})

	return nil
}

func (g *cleanup) Run() error {
	if _, err := os.Stat("/tmp/wag-no-cleanup"); err == nil || g.force {
		os.Remove("/tmp/wag-no-cleanup")
		router.TearDown()
		control.TearDown()
	}
	return nil

}
