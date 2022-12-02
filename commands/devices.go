package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/NHAS/wag/control/wagctl"
)

type devices struct {
	fs *flag.FlagSet

	address string
	action  string
}

func Devices() *devices {
	gc := &devices{
		fs: flag.NewFlagSet("devices", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.address, "address", "", "Address of device")

	gc.fs.Bool("del", false, "Remove device and block wireguard access")
	gc.fs.Bool("list", false, "List wireguard devices")

	gc.fs.Bool("mfa_sessions", false, "Get list of devices with active authorised sessions")

	gc.fs.Bool("unlock", false, "Unlock device")
	gc.fs.Bool("lock", false, "Lock device access to mfa routes")

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
		if g.address == "" {
			return errors.New("address must be supplied")
		}
	case "list", "mfa_sessions":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *devices) Run() error {
	switch g.action {
	case "del":

		err := wagctl.DeleteDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	case "list":

		ds, err := wagctl.ListDevice("")
		if err != nil {
			return err
		}

		fmt.Println("username,address,publickey,authattempts,endpoint")
		for _, device := range ds {
			fmt.Printf("%s,%s,%s,%d,%s\n", device.Username, device.Address, device.Publickey, device.Attempts, device.Endpoint.String())
		}
	case "mfa_sessions":
		sessions, err := wagctl.Sessions()
		if err != nil {
			return err
		}
		fmt.Println(sessions)
	case "lock":

		err := wagctl.LockDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")

	case "unlock":

		err := wagctl.UnlockDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	}

	return nil
}
