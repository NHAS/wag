package commands

import "flag"

type Command interface {
	Check() error
	Run() error
	PrintUsage()
	Name() string
	FlagSet() *flag.FlagSet
}
