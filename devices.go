package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

type devices struct {
	fs *flag.FlagSet

	device string
	config string
	action string
}

func DevicesSubCommand() *devices {
	gc := &devices{
		fs: flag.NewFlagSet("devices", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.action, "action", "list", "del or list devices")
	gc.fs.StringVar(&gc.device, "device", "", "Device address")
	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")

	return gc
}

func (g *devices) Name() string {

	return g.fs.Name()
}

func (g *devices) PrintUsage() {
	g.fs.Usage()
}

func (g *devices) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	err = LoadConfig(g.config)
	if err != nil {
		return err
	}

	g.action = strings.ToLower(g.action)

	switch g.action {
	case "del":
		if g.device == "" {
			return errors.New("Token must be supplied")
		}
	case "list":
	default:
		return errors.New("Invalid action choice")
	}

	err = LoadDb(Config.DatabaseLocation)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	return nil

}

func (g *devices) Run() error {
	switch g.action {
	case "del":

		err := DeleteDevice(g.device)
		if err != nil {
			return errors.New("Could not delete token: " + err.Error())
		}
	case "list":
		result, err := GetDevices()
		if err != nil {
			return err
		}

		for address, properties := range result {
			fmt.Print(address, " ")

			for _, m := range properties {
				fmt.Print(m, " ")
			}
			fmt.Print("\n")
		}
	}

	return nil
}
