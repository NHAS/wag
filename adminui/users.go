package adminui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (au *AdminUI) getUsers(w http.ResponseWriter, r *http.Request) {
	users, err := au.ctrl.ListUsers("")
	if err != nil {
		log.Println("error getting users: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	usersData := []UsersData{}
	for _, u := range users {
		devices, err := au.ctrl.ListDevice(u.Username)
		if err != nil {
			log.Printf("failed to get devices for %q err: %s", u.Username, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		groups, err := au.ctrl.UserGroups(u.Username)
		if err != nil {
			log.Printf("unable to get users groups for user %q: %s", u.Username, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		usersData = append(usersData, UsersData{
			Username: u.Username,
			Locked:   u.Locked,
			Devices:  len(devices),
			Groups:   groups,
			MFAType:  u.MfaType,
		})
	}

	b, err := json.Marshal(usersData)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (au *AdminUI) editUser(w http.ResponseWriter, r *http.Request) {
	var action struct {
		Action    string   `json:"action"`
		Usernames []string `json:"usernames"`
	}

	err := json.NewDecoder(r.Body).Decode(&action)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var errs []string
	for _, username := range action.Usernames {
		var err error
		switch action.Action {
		case "lock":
			err = au.ctrl.LockUser(username)

		case "unlock":
			err = au.ctrl.UnlockUser(username)

		case "resetMFA":
			err = au.ctrl.ResetUserMFA(username)

		default:
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err != nil {
			log.Println("failed to", action.Action, "on user: ", username, "err:", err)
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {

		http.Error(w, fmt.Sprintf("%d/%d failed with errors:\n%s", len(errs), len(action.Usernames), strings.Join(errs, "\n")), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK"))
}

func (au *AdminUI) removeUsers(w http.ResponseWriter, r *http.Request) {

	var usernames []string

	err := json.NewDecoder(r.Body).Decode(&usernames)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	errs := ""

	for _, user := range usernames {
		err := au.ctrl.DeleteUser(user)
		if err != nil {
			log.Println("Error deleting user: ", user, "err: ", err)
			errs = errs + "\n" + err.Error()
		}
	}

	if len(errs) > 0 {
		log.Println("failed to delete users: ", errs)
		http.Error(w, errs, http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK"))
}
