package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	InterfaceTemplate *template.Template = template.Must(template.New("").Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(interfaceTemplate))
	DisplayMFATmpl    *template.Template = template.Must(template.New("").Parse(mfaDisplayTmplt))
	PromptTmpl        *template.Template = template.Must(template.New("").Parse(mfaPromptTmplt))
)

func setMimeType(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	ext := filepath.Ext(r.URL.Path)

	switch ext {
	case ".css":
		headers.Set("Content-Type", "text/css")
	case ".png":
		headers.Set("Content-Type", "image/png")
	case ".jpg":
		headers.Set("Content-Type", "image/jpg")
	case ".svg":
		headers.Set("Content-Type", "image/svg")
	}
}

func embeddedStatic(w http.ResponseWriter, r *http.Request) {

	var err error
	var fileContent []byte

	if fileContent, err = static.ReadFile(filepath.Join("resources", r.URL.Path)); err != nil {
		log.Println("Error getting static: ", err)
		http.NotFound(w, r)
		return
	}

	setMimeType(w, r)

	_, err = w.Write(fileContent)
	if err != nil {
		log.Println("Error writing content")
		http.Error(w, "Unable to write static resource", 500)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	mfaFailed := r.Method == "POST"

	actualIP := GetIP(r.RemoteAddr)

	if isEnforcingMFA(GetIP(actualIP)) {
		data := struct {
			ValidationFailed bool
		}{
			ValidationFailed: mfaFailed,
		}
		err := PromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println("Unable to build template: ", err)
		}
		return
	}

	key, err := GetMFASecret(actualIP)
	if err != nil {
		log.Println(err)
		http.Error(w, "Unknown error", 500)
		return
	}

	image, err := key.Image(200, 200)
	if err != nil {
		log.Println(err)
		http.Error(w, "Unknown error", 500)
		return
	}

	var buff bytes.Buffer
	err = png.Encode(&buff, image)
	if err != nil {
		log.Println(err)
		http.Error(w, "Unknown error", 500)
		return
	}

	data := struct {
		ImageData        string
		AccountName      string
		Key              string
		ValidationFailed bool
	}{
		ImageData:        "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
		AccountName:      key.AccountName(),
		Key:              key.Secret(),
		ValidationFailed: mfaFailed,
	}

	err = DisplayMFATmpl.Execute(w, &data)
	if err != nil {
		log.Println("Unable to build template: ", err)
	}

}

func authorise(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	actualIP := GetIP(r.RemoteAddr)

	err := r.ParseForm()
	if err != nil {
		log.Println("Client sent a weird form: ", err)

		http.Error(w, "Bad request", 400)
		return
	}

	code := r.FormValue("code")

	username, err := ValidateTotpCode(actualIP, code)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if !isEnforcingMFA(actualIP) {
		err := SetMFAEnforcing(actualIP)
		if err != nil {
			log.Println("Didnt set MFA as enforcing", err)
			http.Error(w, "Failed", 500)
		}

		return
	}

	err = AllowDevice(actualIP, 4*time.Hour)
	if err != nil {
		log.Println("Unable to allow device", err)

		http.Error(w, "Failed", 500)
		return
	}

	w.Write([]byte(username + " you're all good to go"))

}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	key, ok := r.URL.Query()["key"]
	if !ok || len(key[0]) < 1 || len(key) > 1 {
		log.Println("No registration key specified, ignoring")

		http.NotFound(w, r)
		return
	}
	username, err := GetRegistrationToken(key[0])
	if err != nil {
		http.NotFound(w, r)
		log.Println(err)
		return
	}

	var publickey, privatekey wgtypes.Key
	pubkeyParam, ok := r.URL.Query()["pubkey"]
	if len(pubkeyParam) == 1 {
		publickey, err = wgtypes.NewKey([]byte(pubkeyParam[0]))
		if err != nil {
			http.Error(w, "Unable to unmarshal the public key", 400)
			return
		}
	} else {
		privatekey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			http.Error(w, "Unable to unmarshal the public key", 400)
			return
		}
		publickey = privatekey.PublicKey()
	}

	address, err := AddDevice(publickey)
	if err != nil {
		log.Println("Unable to add device: ", err)
		http.Error(w, "Error adding device, please contact your sysadmin", 500)
		return
	}

	defer func() {
		if err != nil {
			log.Println("Error: ", err, "Removing device")
			err := RemoveDevice(publickey)
			if err != nil {
				log.Println("Unable to remove wg device: ", err)
			}
		}

	}()

	err = ArmMFAFirstUse(address, publickey.String(), username)
	if err != nil {
		log.Println("Unable to arm mfa: ", err)
		http.Error(w, "Error adding device, please contact your sysadmin", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=wg0.conf")

	i := Interface{
		ClientPrivateKey:  strings.TrimSpace(privatekey.String()),
		ClientAddress:     address,
		ServerAddress:     fmt.Sprintf("%s:%d", Config.ExternalAddress, WgDev.ListenPort),
		ServerPublicKey:   WgDev.PublicKey.String(),
		CapturedAddresses: Config.CapturedAddreses,
	}

	err = InterfaceTemplate.Execute(w, &i)
	if err != nil {
		http.NotFound(w, r)
		log.Println(err)
		return
	}

	//Finish registration process
	err = DeleteRegistrationToken(key[0])
	if err != nil {
		http.NotFound(w, r)
		log.Println(err)
		return
	}

}
