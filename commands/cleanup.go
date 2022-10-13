package commands

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/router"
)

type cleanup struct {
	fs     *flag.FlagSet
	config string
}

func Cleanup() *cleanup {
	gc := &cleanup{
		fs: flag.NewFlagSet("cleanup", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")

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
}

func (g *cleanup) Check() error {
	return nil
}

func (g *cleanup) Run() error {
	if _, err := os.Stat("/tmp/wag-no-cleanup"); err == nil {
		err := os.Remove("/tmp/wag-no-cleanup")
		if err != nil {
			return err
		}
		router.TearDown()
		control.TearDown()
		return exec.Command("/usr/bin/wg-quick", "stop", config.Values().WgDevName).Run()
	}
	return nil

}
