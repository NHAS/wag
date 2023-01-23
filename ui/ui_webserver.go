package ui

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"
)

func StartWebServer() {
	//static := http.FileServer(http.FS(ui.StaticContent))
	static := http.FileServer(http.Dir("ui"))
	http.Handle("/css/", static)
	http.Handle("/js/", static)
	http.Handle("/vendor/", static)
	http.Handle("/img/", static)

	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/management/dashboard.html"))

		d := Dashboard{
			Page: Page{
				Description: "Dashboard",
				Title:       "Dashboard",
				User:        "Ben Bonk",
			},
			Users:              []string{"a"},
			ActiveSessions:     []string{"active"},
			RegistrationTokens: []string{},
			LockedDevices:      []string{"noot"},
			UnenforcedMFA:      0,
		}
		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/management/users/", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/management/users.html"))

		d := Page{
			Description: "Users Management Page",
			Title:       "Users",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/management/users/data", func(w http.ResponseWriter, r *http.Request) {

		b, err := json.Marshal(struct {
			Data []UsersData `json:"data"`
		}{

			Data: []UsersData{
				{
					Username:  "jsmith",
					Devices:   2,
					Enforcing: true,
					Locked:    false,
					DateAdded: time.Now().Format("2006-02-01"),
					Groups:    "",
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	http.HandleFunc("/management/devices/", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/management/devices.html"))

		d := Page{
			Description: "Devices Management Page",
			Title:       "Devices",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/management/devices/data", func(w http.ResponseWriter, r *http.Request) {

		b, err := json.Marshal(struct {
			Data []DevicesData `json:"data"`
		}{

			Data: []DevicesData{
				{
					Owner:             "jsmith",
					Locked:            false,
					InternalIP:        "10.2.2.2",
					PublicKey:         "eMumd56UruVA+zXQ+TAlMIXumaL1s+LR/qzK7ZQAH0A=",
					LastEndpoint:      "2.3.4.5:2929",
					LastHandShakeTime: time.Now().Format("2006-02-01"),
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	http.HandleFunc("/management/registration_tokens/", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/management/registration_tokens.html"))

		d := Page{
			Description: "Registration Tokens Management Page",
			Title:       "Registration",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/management/registration_tokens/data", func(w http.ResponseWriter, r *http.Request) {

		b, err := json.Marshal(struct {
			Data []TokensData `json:"data"`
		}{

			Data: []TokensData{
				{
					Token:      "65b596e1-2369-4dfe-a26f-74ca2efcc7ea",
					Username:   "yartern",
					Groups:     "fronk",
					Overwrites: "",
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	http.HandleFunc("/policy/rules/", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/policy/rules.html"))

		d := Page{
			Description: "Firewall rules",
			Title:       "Rules",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/policy/rules/data", func(w http.ResponseWriter, r *http.Request) {

	})

	http.HandleFunc("/settings/general", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/settings/general.html"))

		d := Page{
			Description: "Wag settings",
			Title:       "Settings - General",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/settings/management_users", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/settings/management_users.html"))

		d := Page{
			Description: "Wag settings",
			Title:       "Settings - Admin Users",
			User:        "Ben Bonk",
		}

		err := data.Execute(w, d)

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/settings/management_users/data", func(w http.ResponseWriter, r *http.Request) {

	})

	http.HandleFunc("/change_password", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/change_password.html"))
		err := data.Execute(w, Page{Description: "Change Password", Title: "Change Password", User: "Ben Bonk"})

		if err != nil {
			log.Fatal(err)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		data := template.Must(template.ParseFiles("ui/template.html", "ui/templates/404.html"))
		err := data.Execute(w, Page{Description: "Dashboard", Title: "Dashboard", User: "Ben Bonk"})

		if err != nil {
			log.Fatal(err)
		}
	})

	err := http.ListenAndServe(":8000", nil)

	if err != nil {
		log.Fatal(err)
	}
}
