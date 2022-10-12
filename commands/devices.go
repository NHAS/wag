package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/control"
)

type devices struct {
	fs *flag.FlagSet

	username string
	action   string
}

func Devices() *devices {
	gc := &devices{
		fs: flag.NewFlagSet("devices", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.username, "username", "", "Username for device")

	gc.fs.Bool("del", false, "Completely remove device blocks wireguard access")
	gc.fs.Bool("list", false, "List devices with 2fa entries")

	gc.fs.Bool("mfa_sessions", false, "Get list of deivces with active authorised sessions")

	gc.fs.Bool("unlock", false, "Unlock a locked account/device")
	gc.fs.Bool("lock", false, "Locked account/device access to mfa routes")

	return gc
}

func (g *devices) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *devices) Name() string {

	return g.fs.Name()
}

func (g *devices) PrintUsage() {
	g.fs.Usage()
}

func (g *devices) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "unlock", "del", "list", "lock", "mfa_sessions":
			g.action = strings.ToLower(f.Name)
		}
	})

	switch g.action {
	case "del", "unlock", "lock":
		if g.username == "" {
			return errors.New("username must be supplied")
		}
	case "list", "mfa_sessions":
	default:
		return errors.New("invalid action choice")
	}

	return nil
}

func (g *devices) Run() error {
	switch g.action {
	case "del":

		err := control.DeleteDevice(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	case "list":

		ds, err := control.ListDevice(g.username)
		if err != nil {
			return err
		}

		fmt.Println("username,address,publickey,enforcingmfa,authattempts")
		for _, device := range ds {
			fmt.Printf("%s,%s,%s,%t,%d\n", device.Username, device.Address, device.Publickey, device.Enforcing, device.Attempts)
		}
	case "mfa_sessions":
		sessions, err := control.Sessions()
		if err != nil {
			return err
		}
		fmt.Println(sessions)
	case "lock":

		err := control.LockDevice(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")

	case "unlock":

		err := control.UnlockDevice(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	}

	return nil
}
