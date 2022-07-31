package commands

import (
	"fmt"
)

type Command interface {
	Init([]string) error
	Run() error
	PrintUsage()
	Name() string
}

func configHelp() {
	fmt.Println("  -config string")
	fmt.Println("    Configuration file location (default \"./config.json\")")
}
