package commands

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/control/wagctl"
)

type firewallCmd struct {
	fs     *flag.FlagSet
	action string
}

func Firewall() *firewallCmd {
	gc := &firewallCmd{
		fs: flag.NewFlagSet("firewall", flag.ContinueOnError),
	}

	gc.fs.Bool("list", false, "List firewall rules")

	return gc
}

func (g *firewallCmd) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *firewallCmd) Name() string {

	return g.fs.Name()
}

func (g *firewallCmd) PrintUsage() {
	g.fs.Usage()
}

func (g *firewallCmd) Check() error {
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

		rules, err := wagctl.FirewallRules()
		if err != nil {
			return err
		}

		b, _ := json.Marshal(rules)

		fmt.Println(string(b))
	}
	return nil

}
