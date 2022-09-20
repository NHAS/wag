package commands

import (
	"flag"
	"fmt"

	"github.com/NHAS/wag/control"
)

type version struct {
	fs *flag.FlagSet
}

func VersionCmd() *version {
	gc := &version{
		fs: flag.NewFlagSet("version", flag.ContinueOnError),
	}

	return gc
}

func (g *version) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *version) Name() string {

	return g.fs.Name()
}

func (g *version) PrintUsage() {
	fmt.Println("Usage of version:")
	fmt.Println("  Print version of wag")
}

func (g *version) Check() error {
	return nil
}

func (g *version) Run() error {

	ver, err := control.GetVersion()
	if err != nil {
		return err
	}

	fmt.Println(ver)

	return nil
}
