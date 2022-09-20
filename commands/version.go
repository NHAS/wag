package commands

import (
	"flag"
	"fmt"
)

var Version string

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

	if Version == "" {
		Version = "UNKNOWN"
	}

	fmt.Println(Version)

	return nil
}
