package main

import (
	"embed"
)

//go:embed resources/interface.tmpl
var interfaceTemplate string

//go:embed resources/displaymfa.html
var mfaDisplayTmplt string

//go:embed resources/promptmfa.html
var mfaPromptTmplt string

//go:embed resources/static
var static embed.FS

type Interface struct {
	ClientPrivateKey string
	ClientAddress    string

	ServerAddress     string
	ServerPublicKey   string
	CapturedAddresses []string
}
