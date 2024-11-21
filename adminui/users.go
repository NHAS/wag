package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

func (au *AdminUI) getUsers(w http.ResponseWriter, r *http.Request) {
	users, err := au.ctrl.ListUsers("")
	if err != nil {
		log.Println("error getting users: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	usersData := []UsersData{}
	for _, u := range users {
		devices, err := au.ctrl.ListDevice(u.Username)
		if err != nil {
			log.Printf("failed to get devices for %q err: %s", u.Username, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		groups, err := au.ctrl.UserGroups(u.Username)
		if err != nil {
			log.Printf("unable to get users groups for user %q: %s", u.Username, err)
			w.WriteHeader(http.StatusInternalServerError)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usersData)
}

func (au *AdminUI) editUser(w http.ResponseWriter, r *http.Request) {
	var (
		action EditUsersDTO
		err    error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&action)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var errs []error
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
			errs = append(errs, err)
		}
	}

	err = errors.Join(errs...)

	if err != nil {

		w.WriteHeader(http.StatusInternalServerError)
		err = fmt.Errorf("%d/%d failed to %s\n%s", len(errs), len(action.Usernames), action.Action, errors.Join(errs...).Error())
		return
	}
}

func (au *AdminUI) removeUsers(w http.ResponseWriter, r *http.Request) {

	var (
		usernames []string
		err       error
	)

	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&usernames)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var errs []error

	for _, user := range usernames {
		err := au.ctrl.DeleteUser(user)
		if err != nil {
			errs = append(errs, err)
		}
	}

	err = errors.Join(errs...)
	if err != nil {
		log.Println("failed to delete users: ", errs)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
