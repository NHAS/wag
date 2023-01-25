package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type registration struct {
	fs *flag.FlagSet

	token    string
	username string
	socket   string
	action   string

	groups       arrayFlags
	groupsString string
	overwrite    string
}

func Registration() *registration {
	gc := &registration{
		fs: flag.NewFlagSet("registration", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.token, "token", "", "Manually set registration token (Optional)")
	gc.fs.StringVar(&gc.username, "username", "", "User to add device to")

	gc.fs.Var(&gc.groups, "group", "Manually set user group (can supply multiple -group, or use -groups for , delimited group list)")
	gc.fs.StringVar(&gc.groupsString, "groups", "", "Set user groups manually, ',' delimited list of groups")

	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag instance to act on")

	gc.fs.StringVar(&gc.overwrite, "overwrite", "", "Add registration token for an existing user device, will overwrite wireguard public key (but not 2FA)")

	gc.fs.Bool("add", false, "Create a new enrolment token")
	gc.fs.Bool("del", false, "Delete existing enrolment token")
	gc.fs.Bool("list", false, "List tokens")

	return gc
}

func (g *registration) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *registration) Name() string {

	return g.fs.Name()
}

func (g *registration) PrintUsage() {
	g.fs.Usage()
}

func (g *registration) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "add", "del", "list":
			g.action = strings.ToLower(f.Name)
		}
	})

	if len(g.groupsString) != 0 {
		g.groups = append(g.groups, strings.Split(g.groupsString, ",")...)
	}

	for i := range g.groups {
		if !strings.HasPrefix(g.groups[i], "group:") {
			g.groups[i] = "group:" + g.groups[i]
		}
	}

	switch g.action {
	case "add":
		if g.username == "" {
			return errors.New("Username must be supplied")
		}

	case "del":
		if g.token == "" && g.username == "" {
			return errors.New("Token or username must be supplied")
		}
	case "list":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil

}

func (g *registration) Run() error {

	ctl := wagctl.NewControlClient(g.socket)

	switch g.action {
	case "add":

		result, err := ctl.NewRegistration(g.token, g.username, g.overwrite, g.groups...)
		if err != nil {
			return err
		}

		fmt.Printf("token,username\n")
		fmt.Printf("%s,%s\n", result.Token, result.Username)

	case "del":

		id := g.token
		if id == "" {
			id = g.username
		}

		if err := ctl.DeleteRegistration(id); err != nil {
			return err
		}

		fmt.Printf("OK")

	case "list":
		tokens, err := ctl.Registrations()
		if err != nil {
			return err
		}

		fmt.Println("token,username,overwrites,groups")
		for _, token := range tokens {
			fmt.Printf("%s,%s,%s,%s\n", token.Token, token.Username, token.Overwrites, token.Groups)
		}
	}

	return nil
}
