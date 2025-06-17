package resources

import (
	"embed"
	"html/template"
	"io"
	"path"
)

type WireguardConfig struct {
	ClientPrivateKey   string
	ClientAddress      string
	ClientPresharedKey string

	ServerAddress     string
	ServerPublicKey   string
	CapturedAddresses []string
	DNS               []string
}
type QrCodeEnrolmentDisplay struct {
	ImageData template.URL
	Username  string
}

//go:embed templates/*
var templates embed.FS

func Render(page string, out io.Writer, data interface{}) error {
	return RenderWithFuncs(page, out, data, nil)
}

func RenderWithFuncs(page string, out io.Writer, data interface{}, templateFuncs template.FuncMap) error {

	currentTemplate := template.Must(template.New(path.Base(page)).Funcs(templateFuncs).ParseFS(templates, "templates/"+page))

	return currentTemplate.Execute(out, data)
}
