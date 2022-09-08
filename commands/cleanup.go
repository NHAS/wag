package commands

import (
	"flag"
	"fmt"
	"os/exec"
	"wag/config"
	"wag/router"
)

type cleanup struct {
	fs *flag.FlagSet
}

func Cleanup() *cleanup {
	gc := &cleanup{
		fs: flag.NewFlagSet("cleanup", flag.ContinueOnError),
	}

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

	router.TearDown()

	cmd := exec.Command("/usr/bin/wg-quick", "stop", config.Values().WgDevName)

	return cmd.Run()

}
