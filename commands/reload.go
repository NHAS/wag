package commands

import (
	"flag"
	"fmt"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/control/wagctl"
)

type reload struct {
	fs *flag.FlagSet

	socket string
}

func Reload() *reload {
	gc := &reload{
		fs: flag.NewFlagSet("reload", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag socket to act on")

	return gc
}

func (g *reload) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *reload) Name() string {

	return g.fs.Name()
}

func (g *reload) PrintUsage() {
	fmt.Println("Usage of reload:")
	fmt.Println("  Reload ACLs from config.json")
}

func (g *reload) Check() error {

	return nil
}

func (g *reload) Run() error {

	return wagctl.NewControlClient(g.socket).ConfigReload()
}
