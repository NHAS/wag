package commands

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"wag/config"
	"wag/database"
)

type registration struct {
	fs *flag.FlagSet

	token    string
	username string
	action   string
}

func Registration() *registration {
	gc := &registration{
		fs: flag.NewFlagSet("registration", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.token, "token", "", "Manually set registration token (Optional)")
	gc.fs.StringVar(&gc.username, "username", "", "Username of device")

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
		return errors.New("Invalid action choice: " + g.action)
	}

	err := database.Load(config.Values().DatabaseLocation, config.Values().Issuer, config.Values().Lockout)
	if err != nil {
		return fmt.Errorf("Cannot load database: %v", err)
	}

	return nil

}

func (g *registration) Run() error {
	switch g.action {
	case "add":
		if g.token != "" {
			err := database.AddRegistrationToken(g.token, g.username)
			if err != nil {
				return err
			}

			fmt.Println("OK ", g.token, g.username)

			return nil
		}

		token, err := database.GenerateToken(g.username)
		if err != nil {
			return err
		}

		fmt.Printf("token,username\n")
		fmt.Printf("%s,%s\n", token, g.username)
	case "del":

		err := database.DeleteRegistrationToken(g.token)
		if err != nil {
			return errors.New("Could not delete token: " + err.Error())
		}
		fmt.Println("OK")
	case "list":
		result, err := database.GetRegistrationTokens()
		if err != nil {
			return err
		}

		fmt.Println("token,username")
		for token, username := range result {
			fmt.Printf("%s,%s\n", token, username)
		}
	}

	return nil
}
