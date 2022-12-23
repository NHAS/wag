package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/control/wagctl"
)

type devices struct {
	fs *flag.FlagSet

	address, username, socket string
	action                    string
}

func Devices() *devices {
	gc := &devices{
		fs: flag.NewFlagSet("devices", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.address, "address", "", "Address of device")
	gc.fs.StringVar(&gc.socket, "socket", control.DefaultWagSocket, "Wag control socket to act on")

	gc.fs.StringVar(&gc.username, "username", "", "Owner of device (indicates that command acts on all devices owned by user)")

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
		if g.address == "" && g.username == "" {
			return errors.New("address or username must be supplied")
		}
	case "list", "mfa_sessions":
	default:
		return errors.New("Unknown flag: " + g.action)
	}

	return nil
}

func (g *devices) Run() error {

	ctl := wagctl.NewControlClient(g.socket)

	switch g.action {
	case "del":
		if g.username != "" {
			ds, err := ctl.ListDevice(g.username)
			if err != nil {
				return err

			}
			fmt.Println("deleting all devices for: ", g.username)
			time.Sleep(3 * time.Second)

			for _, device := range ds {
				fmt.Println("deleting ", device.Address)
				err := ctl.DeleteDevice(device.Address)
				if err != nil {
					return err
				}
			}

			fmt.Println("OK")
			return nil
		}

		err := ctl.DeleteDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	case "list":

		ds, err := ctl.ListDevice("")
		if err != nil {
			return err
		}

		fmt.Println("username,address,publickey,authattempts,endpoint")
		for _, device := range ds {
			fmt.Printf("%s,%s,%s,%d,%s\n", device.Username, device.Address, device.Publickey, device.Attempts, device.Endpoint.String())
		}
	case "mfa_sessions":
		sessions, err := ctl.Sessions()
		if err != nil {
			return err
		}
		fmt.Println(sessions)
	case "lock":

		if g.username != "" {
			ds, err := ctl.ListDevice(g.username)
			if err != nil {
				return err

			}

			for _, device := range ds {
				fmt.Println("locking ", device)
				err := ctl.LockDevice(device.Address)
				if err != nil {
					return err
				}
			}

			fmt.Println("OK")
			return nil
		}

		err := ctl.LockDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")

	case "unlock":

		if g.username != "" {

			ds, err := ctl.ListDevice(g.username)
			if err != nil {
				return err

			}

			for _, device := range ds {
				err := ctl.UnlockDevice(device.Address)
				if err != nil {
					return err
				}
			}

			fmt.Println("OK")
			return nil
		}

		err := ctl.UnlockDevice(g.address)
		if err != nil {
			return err
		}

		fmt.Println("OK")
	}

	return nil
}
