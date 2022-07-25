package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

type Runner interface {
	Init([]string) error
	Run() error
	PrintUsage()
	Name() string
}

var cmds = []Runner{
	RegistrationSubCommand(),
	ServerSubCommand(),
	DevicesSubCommand(),
}

func help() {
	fmt.Println("Wag")
	fmt.Println("Management of wireguard enrollments, and 2fa")

	for _, r := range cmds {
		r.PrintUsage()
		fmt.Print("\n")
	}
}

func root(args []string) error {
	if len(args) < 1 {
		help()
		return errors.New("No subcommand specified")
	}

	subcommand := os.Args[1]

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			err := cmd.Init(os.Args[2:])
			if err != nil {
				if err != flag.ErrHelp {
					fmt.Println("Error: ", err.Error())
					cmd.PrintUsage()
				}
				return nil
			}
			return cmd.Run()
		}
	}

	help()
	if subcommand == "-h" || subcommand == "--help" || subcommand == "-help" {
		return nil
	}
	return fmt.Errorf("Unknown subcommand: %s", subcommand)
}

func main() {

	if err := root(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
