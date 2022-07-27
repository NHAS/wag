package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"wag/commands"
	"wag/config"
)

var cmds = []commands.Command{
	commands.Start(),

	commands.Registration(),
	commands.Devices(),
}

func help(full bool) {
	fmt.Println("\t\t\tWag")

	if full {
		fmt.Println("Adds 2fa and device enrolment to wireguard deployments.")
		fmt.Print("\n")
	}

	fmt.Print("Supported commands: ")
	for i, r := range cmds {
		fmt.Print(r.Name())
		if i != len(cmds)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Print("\n")

	if full {
		fmt.Println("All commands require:")
		fmt.Println("  -config string")
		fmt.Println("    Configuration file location (default \"./config.json\")")
		fmt.Print("\n")

		for _, r := range cmds {
			r.PrintUsage()
			fmt.Print("\n")
		}
	}
}

func root(args []string) error {
	if len(args) < 1 {
		help(false)
		fmt.Println("No submodule specified (do you need (-h)elp?)")
		return nil
	}

	subcommand := os.Args[1]

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {

			var configLocation string

			configfs := flag.NewFlagSet("config", flag.ContinueOnError)
			configfs.Usage = func() {}
			configfs.SetOutput(io.Discard)

			configfs.StringVar(&configLocation, "config", "./config.json", "Configuration file location")

			configfs.Parse(os.Args[2:])

			config, err := config.New(configLocation)
			if err != nil {
				return err
			}

			err = cmd.Init(os.Args[2:], config)
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

	needsHelp := subcommand == "-h" || subcommand == "--help" || subcommand == "-help"

	help(needsHelp)
	if !needsHelp {
		fmt.Printf("Unknown subcommand: %s\n", subcommand)
	}

	return nil
}

func main() {

	if err := root(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
