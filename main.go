package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/NHAS/wag/commands"
)

var cmds = []commands.Command{
	commands.Start(),
	commands.Cleanup(),
	commands.Reload(),

	commands.Registration(),
	commands.Devices(),
	commands.Firewall(),

	commands.VersionCmd(),
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

			if err := cmd.Check(); err != nil {
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

	syscall.Umask(017)

	if err := root(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
