package commands

import (
	"flag"
	"fmt"
	"log"
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
	g.fs.PrintDefaults()
}

func (g *cleanup) Check() error {

	err := config.Load(g.config)
	if err != nil {
		return err
	}

	return nil
}

func (g *cleanup) Run() error {
	log.Println("Cleaning up")

	//https://man7.org/linux/man-pages/man5/systemd.exec.5.html
	result := os.Getenv("EXIT_STATUS")
	//0 is we returned fine, so this firewall rules will be removed anyway
	//3 is executed when Shutdown(false) is called, preventing cleanup

	if result != "0" && result != "3" {
		router.TearDown()
		control.TearDown()
		return exec.Command("/usr/bin/wg-quick", "down", config.Values().WgDevName).Run()
	}

	return nil
}
