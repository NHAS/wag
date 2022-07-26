package commands

import (
	"fmt"
	"wag/config"
)

type Command interface {
	Init([]string, config.Config) error
	Run() error
	PrintUsage()
	Name() string
}

func configHelp() {
	fmt.Println("  -config string")
	fmt.Println("    Configuration file location (default \"./config.json\")")
}
