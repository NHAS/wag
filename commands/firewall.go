package commands

import (
	"errors"
	"flag"
	"strings"

	"github.com/NHAS/wag/pkg/control"
)

type firewallCmd struct {
	fs             *flag.FlagSet
	action, socket string
}

func Firewall() *firewallCmd {
	gc := &firewallCmd{
		fs: flag.NewFlagSet("firewall", flag.ContinueOnError),
	}

	gc.fs.Bool("list", false, "List firewall rules")
	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag control socket to act on")

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

	//ctl := wagctl.NewControlClient(g.socket)

	switch g.action {
	case "list":

		// rules, err := ctl.FirewallRules()
		// if err != nil {
		// 	return err
		// }

		// b, _ := json.Marshal(rules)

		// fmt.Println(string(b))
	}
	return nil

}
