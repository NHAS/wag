package resources

import (
	"embed"
	"html/template"
	"strings"
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

type Msg struct {
	Message    string
	URL        string
	HelpMail   string
	NumMethods int
}

var InterfaceTemplate *template.Template = template.Must(template.New("").Funcs(template.FuncMap{
	"StringsJoin": strings.Join,
	"Unescape":    func(s string) template.HTML { return template.HTML(s) },
}).Parse(interfaceTemplate))

type Menu struct {
	MFAMethods  []MenuEntry
	LastElement int
}

type MenuEntry struct {
	Path, FriendlyName string
}

//go:embed register_mfa.html
var mfaRegistrationMenu string

var MFARegistrationMenu *template.Template = template.Must(template.New("").Parse(mfaRegistrationMenu))

//go:embed oidc_error.html
var oidcError string

var OIDCMFATemplate *template.Template = template.Must(template.New("").Parse(oidcError))

//go:embed register_mfa_totp.html
var totpRegistration string

var TotpMFATemplate *template.Template = template.Must(template.New("").Parse(totpRegistration))

//go:embed register_mfa_webauthn.html
var webauthnRegistration string

var WebauthnMFATemplate *template.Template = template.Must(template.New("").Parse(webauthnRegistration))

//go:embed prompt_mfa_totp.html
var totpPrompt string

var TotpMFAPromptTmpl *template.Template = template.Must(template.New("").Parse(totpPrompt))

//go:embed prompt_mfa_webauthn.html
var webauthnPrompt string

var WebauthnMFAPromptTmpl *template.Template = template.Must(template.New("").Parse(webauthnPrompt))

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
