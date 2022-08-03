package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"wag/control"
)

type firewallCmd struct {
	fs      *flag.FlagSet
	address string
	action  string
}

func Firewall() *firewallCmd {
	gc := &firewallCmd{
		fs: flag.NewFlagSet("firewall", flag.ContinueOnError),
	}

	gc.fs.Bool("list", false, "List firewall rules, ")

	return gc
}

func (g *firewallCmd) Name() string {

	return g.fs.Name()
}

func (g *firewallCmd) PrintUsage() {
	g.fs.Usage()
}

func (g *firewallCmd) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "list":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "list":
	default:
		return errors.New("invalid action choice")
	}

	return nil
}

func (g *firewallCmd) Run() error {
	switch g.action {
	case "list":
		fmt.Println(control.FirewallRules())
	}
	return nil

}
