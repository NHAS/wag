package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

type webadmin struct {
	fs *flag.FlagSet

	username, socket string
	action           string
}

func Webadmin() *webadmin {
	gc := &webadmin{
		fs: flag.NewFlagSet("webadmin", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.username, "username", "", "Username to act upon")
	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag instance control socket")

	gc.fs.Bool("del", false, "Delete user and all associated devices")
	gc.fs.Bool("list", false, "List web administration users, if '-username' supply will filter by user")

	gc.fs.Bool("lockaccount", false, "Lock account disable authention from any device, deauthenticates user active sessions")
	gc.fs.Bool("unlockaccount", false, "Unlock a locked account, does not unlock specific device locks (use device -unlock -username <> for that)")

	return gc
}

func (g *webadmin) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *webadmin) Name() string {

	return g.fs.Name()
}

func (g *webadmin) PrintUsage() {
	g.fs.Usage()
}

func (g *webadmin) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "lockaccount", "unlockaccount", "del", "list":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "del", "unlockaccount", "lockaccount":
		if g.username == "" {
			return errors.New("address must be supplied")
		}
	case "list":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *webadmin) Run() error {
	ctl := wagctl.NewControlClient(g.socket)

	switch g.action {
	case "del":

		err := ctl.DeleteUser(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")

	case "list":

		users, err := ctl.ListUsers(g.username)
		if err != nil {
			return err
		}

		fmt.Println("username,locked,enforcingmfa")
		for _, user := range users {
			fmt.Printf("%s,%t,%t\n", user.Username, user.Locked, user.Enforcing)
		}
	case "lockaccount":

		err := ctl.LockUser(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")

	case "unlockaccount":

		err := ctl.UnlockUser(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	}

	return nil
}
