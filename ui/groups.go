package ui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
)

func groupsUI(w http.ResponseWriter, r *http.Request) {
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
		Update:       getUpdate(),
		Description:  "Groups",
		Title:        "Groups",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "policy/groups.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render groups page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func groups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := ctrl.GetGroups()
		if err != nil {
			log.Println("unable to marshal rules data: ", err)
			http.Error(w, "Server error", 500)
			return
		}
		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal groups data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var groupsToRemove []string
		err := json.NewDecoder(r.Body).Decode(&groupsToRemove)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group names to remove: ", err)
			return
		}

		if err := ctrl.RemoveGroup(groupsToRemove); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error removing groups: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "PUT":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to edit new group/s: ", err)
			return
		}

		if err := ctrl.EditGroup(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error editing group: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "POST":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to add new group: ", err)
			return
		}

		if err := ctrl.AddGroup(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error adding group: ", err)
			return
		}

		w.Write([]byte("OK"))
	default:
		http.NotFound(w, r)
		return
	}

}
