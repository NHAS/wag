package ui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/data"
)

func usersUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{
		Notification: getUpdate(),
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

	switch r.Method {
	case "GET":
		users, err := ctrl.ListUsers("")
		if err != nil {
			log.Println("error getting users: ", err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		usersData := []UsersData{}

		for _, u := range users {
			devices, _ := ctrl.ListDevice(u.Username)

			groups, err := data.GetUserGroupMembership(u.Username)
			if err != nil {
				log.Println("unable to get users groups: ", err)
				http.Error(w, "Server error", 500)
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
			log.Println("unable to marshal users data: ", err)
			http.Error(w, "Server error", 500)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		var action struct {
			Action    string   `json:"action"`
			Usernames []string `json:"usernames"`
		}

		err := json.NewDecoder(r.Body).Decode(&action)
		if err != nil {
			http.Error(w, "Bad request", 400)
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
				http.Error(w, "invalid action", 400)
				return
			}

			if err != nil {
				errs = append(errs, err.Error())
			}
		}

		if len(errs) > 0 {
			http.Error(w, fmt.Sprintf("%d/%d failed with errors:\n%s", len(errs), len(action.Usernames), strings.Join(errs, "\n")), 400)
			return
		}

		w.Write([]byte("OK"))

	case "DELETE":
		var usernames []string

		err := json.NewDecoder(r.Body).Decode(&usernames)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, user := range usernames {
			err := ctrl.DeleteUser(user)
			if err != nil {
				log.Println("Error deleting user: ", user, "err: ", err)
			}
		}
		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}
