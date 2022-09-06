package commands

import (
	"flag"
	"fmt"
	"wag/control"
)

type reload struct {
	fs *flag.FlagSet
}

func Reload() *reload {
	gc := &reload{
		fs: flag.NewFlagSet("reload", flag.ContinueOnError),
	}

	return gc
}

func (g *reload) Name() string {

	return g.fs.Name()
}

func (g *reload) PrintUsage() {
	fmt.Println("Usage of reload:")
	fmt.Println("  Reload ACLs from config.json")
}

func (g *reload) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	return nil
}

func (g *reload) Run() error {

	return control.ConfigReload()
}
