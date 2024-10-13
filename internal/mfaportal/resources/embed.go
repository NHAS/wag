package resources

import (
	"embed"
	"html/template"
	"io"
	"path"

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

func Render(page string, out io.Writer, data interface{}) error {
	return RenderWithFuncs(page, out, data, nil)
}

func RenderWithFuncs(page string, out io.Writer, data interface{}, templateFuncs template.FuncMap) error {
	var currentTemplate *template.Template
	if len(config.Values.MFATemplatesDirectory) != 0 {
		currentTemplate = template.Must(template.New(path.Base(page)).Funcs(templateFuncs).ParseFiles(path.Join(config.Values.MFATemplatesDirectory, page)))
	} else {
		currentTemplate = template.Must(template.New(path.Base(page)).Funcs(templateFuncs).ParseFS(embeddedUI, "templates/"+page))
	}

	return currentTemplate.Execute(out, data)
}
