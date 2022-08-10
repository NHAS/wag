package commands

type Command interface {
	Init([]string) error
	Run() error
	PrintUsage()
	Name() string
}
