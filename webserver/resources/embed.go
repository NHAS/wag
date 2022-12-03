package resources

import (
	"embed"
	"strings"
	"text/template"
)

//go:embed interface.tmpl
var interfaceTemplate string

type Interface struct {
	ClientPrivateKey string
	ClientAddress    string

	ServerAddress     string
	ServerPublicKey   string
	CapturedAddresses []string
	DNS               []string
}

var InterfaceTemplate *template.Template = template.Must(template.New("").Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(interfaceTemplate))

//go:embed displaymfa.html
var mfaDisplayTmplt string

type MfaDisplay struct {
	ImageData   string
	AccountName string
	Key         string
	Message     string
}

var DisplayMFATmpl *template.Template = template.Must(template.New("").Parse(mfaDisplayTmplt))

//go:embed promptmfa.html
var mfaPromptTmplt string

type MfaPrompt struct {
	Message  string
	HelpMail string
}

var PromptTmpl *template.Template = template.Must(template.New("").Parse(mfaPromptTmplt))

//go:embed qrcode_registration.html
var qrcodeRegistrationDisplayTmplt string

type QrCodeRegistrationDisplay struct {
	ImageData string
	Username  string
}

var DisplayRegistrationAsQRCodeTmpl *template.Template = template.Must(template.New("").Parse(qrcodeRegistrationDisplayTmplt))

// Not a template
//
//go:embed success.html
var MfaSuccess string

//go:embed static
var Static embed.FS
