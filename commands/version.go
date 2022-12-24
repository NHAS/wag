package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/control/wagctl"
	"github.com/NHAS/wag/router"
)

type version struct {
	fs     *flag.FlagSet
	action string
	socket string
}

func VersionCmd() *version {
	gc := &version{
		fs: flag.NewFlagSet("version", flag.ContinueOnError),
	}

	gc.fs.Bool("local", false, "do not connect to the running wag server, print local binary version information (useful for using with upgrade)")
	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag socket to act on")

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
	g.fs.PrintDefaults()
}

func (g *version) Check() error {

	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "local":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "local":
	case "":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *version) Run() error {

	ctl := wagctl.NewControlClient(g.socket)

	if g.action == "" {

		ver, err := ctl.GetVersion()
		if err != nil {
			return err
		}

		hash, err := ctl.GetBPFVersion()
		if err != nil {
			return err
		}

		fmt.Println("remote")
		fmt.Println("Version:", ver)
		fmt.Println("Hash:", hash)
		return nil
	}

	fmt.Println("local")
	fmt.Println("Version:", config.Version)
	fmt.Println("Hash:", router.GetBPFHash())

	return nil
}
