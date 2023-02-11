package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

type users struct {
	fs *flag.FlagSet

	username, socket string
	action           string
}

func Users() *users {
	gc := &users{
		fs: flag.NewFlagSet("users", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.username, "username", "", "Username to act upon")
	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag instance control socket")

	gc.fs.Bool("del", false, "Delete user and all associated devices")
	gc.fs.Bool("list", false, "List users, if '-username' supply will filter by user")

	gc.fs.Bool("lockaccount", false, "Lock account disable authention from any device, deauthenticates user active sessions")
	gc.fs.Bool("unlockaccount", false, "Unlock a locked account, does not unlock specific device locks (use device -unlock -username <> for that)")

	gc.fs.Bool("reset-mfa", false, "Reset MFA details, invalids all session and set MFA to be shown")

	return gc
}

func (g *users) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *users) Name() string {

	return g.fs.Name()
}

func (g *users) PrintUsage() {
	g.fs.Usage()
}

func (g *users) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "lockaccount", "unlockaccount", "del", "list", "reset-mfa":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "del", "unlockaccount", "lockaccount", "reset-mfa":
		if g.username == "" {
			return errors.New("username must be supplied")
		}
	case "list":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *users) Run() error {
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
	case "reset-mfa":
		err := ctl.ResetUserMFA(g.username)
		if err != nil {
			return err
		}
		fmt.Println("OK")
	}

	return nil
}
