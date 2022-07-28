package commands

import (
	"flag"
	"fmt"
	"os/exec"
	"wag/config"
	"wag/firewall"
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

func (g *cleanup) Name() string {

	return g.fs.Name()
}

func (g *cleanup) PrintUsage() {
	fmt.Println("Usage of cleanup:")
	fmt.Println("  -config string")
	fmt.Println("    Configuration file location (default \"./config.json\")")
}

func (g *cleanup) Init(args []string, config config.Config) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	firewall.TearDown()

	cmd := exec.Command("/usr/bin/wg-quick", "stop", config.WgDevName)

	return cmd.Run()

}

func (g *cleanup) Run() error {

	return nil
}
