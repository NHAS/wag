package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

type registration struct {
	fs *flag.FlagSet

	token    string
	username string
	config   string
	action   string
}

func RegistrationSubCommand() *registration {
	gc := &registration{
		fs: flag.NewFlagSet("registration", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.action, "action", "add", "add, del or list registration tokens")
	gc.fs.StringVar(&gc.token, "token", "", "Manually set registration token (Optional)")
	gc.fs.StringVar(&gc.username, "username", "", "Username of device")
	gc.fs.StringVar(&gc.config, "config", "./config.json", "Configuration file location")

	return gc
}

func (g *registration) Name() string {

	return g.fs.Name()
}

func (g *registration) PrintUsage() {
	g.fs.Usage()
}

func (g *registration) Init(args []string) error {
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
	case "add":
		if g.username == "" {
			return errors.New("Username must be supplied")
		}

	case "del":
		if g.token == "" {
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

func (g *registration) Run() error {
	switch g.action {
	case "add":
		if g.token != "" {
			err := AddRegistrationToken(g.token, g.username)
			if err != nil {
				return err
			}

			fmt.Println("OK ", g.token, g.username)

			return nil
		}

		token, err := GenerateToken(g.username)
		if err != nil {
			return err
		}

		fmt.Println("OK ", token, g.username)
	case "del":

		err := DeleteRegistrationToken(g.token)
		if err != nil {
			return errors.New("Could not delete token: " + err.Error())
		}
	case "list":
		result, err := GetRegistrationTokens()
		if err != nil {
			return err
		}

		for token, username := range result {
			fmt.Println(token, " ", username)
		}
	}

	return nil
}
