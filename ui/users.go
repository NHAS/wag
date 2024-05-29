package ui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func usersUI(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description:  "Users Management Page",
		Title:        "Users",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "management/users.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render users page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func manageUsers(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.Method {
	case "GET":
		users, err := ctrl.ListUsers("")
		if err != nil {
			log.Println("error getting users: ", err)

			w.WriteHeader(http.StatusInternalServerError)
			renderDefaults(w, r, nil, "error.html")
			return
		}

		usersData := []UsersData{}
		for _, u := range users {
			devices, err := ctrl.ListDevice(u.Username)
			if err != nil {
				log.Println("failed to get devices for ", u.Username, "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			groups, err := ctrl.UserGroups(u.Username)
			if err != nil {
				log.Println("unable to get users groups: ", err)
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
		return
	case "PUT":
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
				err = ctrl.LockUser(username)

			case "unlock":
				err = ctrl.UnlockUser(username)

			case "resetMFA":
				err = ctrl.ResetUserMFA(username)

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
		return

	case "DELETE":
		var usernames []string

		err := json.NewDecoder(r.Body).Decode(&usernames)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		errs := ""

		for _, user := range usernames {
			err := ctrl.DeleteUser(user)
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
		return

	default:
		http.NotFound(w, r)
	}

}
