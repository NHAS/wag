package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

type modifyConfig struct {
	fs *flag.FlagSet

	key, value, action string

	socket string
}

func ModifyConfig() *modifyConfig {
	gc := &modifyConfig{
		fs: flag.NewFlagSet("config", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag control socket to act on")

	gc.fs.StringVar(&gc.key, "key", "", "Key to set or get")
	gc.fs.StringVar(&gc.value, "value", "", "Value to set (put only)")

	gc.fs.Bool("get", false, "Get key value")
	gc.fs.Bool("put", false, "Set key value")

	return gc
}

func (g *modifyConfig) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *modifyConfig) Name() string {

	return g.fs.Name()
}

func (g *modifyConfig) PrintUsage() {
	g.fs.Usage()
}

func (g *modifyConfig) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "get", "put":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "get":
		if g.value != "" {
			return errors.New("value supplied when getting")
		}
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *modifyConfig) Run() error {

	ctl := wagctl.NewControlClient(g.socket)

	switch g.action {
	case "put":
		err := ctl.PutDBKey(g.key, g.value)
		if err != nil {
			return err
		}

		fmt.Println("OK!")
	case "get":
		contents, err := ctl.GetDBKey(g.key)
		if err != nil {
			return err
		}

		fmt.Println(contents)
	}

	return nil
}
