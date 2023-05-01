package resources

import (
	"embed"
	"html/template"
	"io"

	"github.com/NHAS/wag/internal/config"
)

type Interface struct {
	ClientPrivateKey   string
	ClientAddress      string
	ClientPresharedKey string

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

type Menu struct {
	MFAMethods  []MenuEntry
	LastElement int
}

type MenuEntry struct {
	Path, FriendlyName string
}

type QrCodeRegistrationDisplay struct {
	ImageData template.URL
	Username  string
}

//go:embed templates/*
var embeddedUI embed.FS

//go:embed static
var Static embed.FS

// var InterfaceTemplate *template.Template = template.Must(template.New("").Funcs(template.FuncMap{
// 	"StringsJoin": strings.Join,
// 	"Unescape":    func(s string) template.HTML { return template.HTML(s) },
// }).Parse(interfaceTemplate))

func Render(page string, out io.Writer, data interface{}) error {
	return RenderWithFuncs(page, out, data, nil)
}

func RenderWithFuncs(page string, out io.Writer, data interface{}, templateFuncs template.FuncMap) error {
	var currentTemplate *template.Template
	if len(config.Values().MFATemplatesDirectory) != 0 {
		currentTemplate = template.Must(template.New("").Funcs(templateFuncs).ParseFiles(page))
	} else {
		currentTemplate = template.Must(template.New("").Funcs(templateFuncs).ParseFS(embeddedUI, page))
	}

	return currentTemplate.Execute(out, data)
}
