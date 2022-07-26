package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"wag/config"
	"wag/database"
)

type devices struct {
	fs *flag.FlagSet

	device string
	action string
}

func Devices() *devices {
	gc := &devices{
		fs: flag.NewFlagSet("devices", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.action, "action", "list", "del, list, reset devices")

	gc.fs.StringVar(&gc.device, "device", "", "Device address")

	gc.fs.Bool("del", false, "Delete device, this disallows any 2fa attempts")
	gc.fs.Bool("list", false, "List devices devices with 2fa entries")
	gc.fs.Bool("reset", false, "Reset locked account/device")

	return gc
}

func (g *devices) Name() string {

	return g.fs.Name()
}

func (g *devices) PrintUsage() {
	g.fs.Usage()
}

func (g *devices) Init(args []string, config config.Config) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "reset", "del", "list":
			g.action = strings.ToLower(f.Name)
		}
	})

	g.action = strings.ToLower(g.action)

	switch g.action {
	case "del", "reset":
		if g.device == "" {
			return errors.New("Device must be supplied")
		}
	case "list":
	default:
		return errors.New("Invalid action choice")
	}

	err = database.Load(config.DatabaseLocation, config.Issuer, config.Lockout)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	return nil

}

func (g *devices) Run() error {
	switch g.action {
	case "del":

		err := database.DeleteDevice(g.device)
		if err != nil {
			return errors.New("Could not delete token: " + err.Error())
		}
	case "list":
		result, err := database.GetDevices()
		if err != nil {
			return err
		}

		for address, properties := range result {
			fmt.Printf(address, "%+v\n", properties)
		}
	case "reset":
		err := database.SetAttemptsLeft(g.device, 0)
		if err != nil {
			return errors.New("Could not reset device authentication attempts: " + err.Error())
		}
	}

	return nil
}
