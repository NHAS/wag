package ui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
)

func policiesUI(w http.ResponseWriter, r *http.Request) {
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
		Description:  "Firewall rules",
		Title:        "Rules",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "policy/rules.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render rules page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := ctrl.GetPolicies()
		if err != nil {
			log.Println("unable to get policies: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal policies data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var policiesToRemove []string
		err := json.NewDecoder(r.Body).Decode(&policiesToRemove)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding policy names to remove: ", err)
			return
		}

		if err := ctrl.RemovePolicies(policiesToRemove); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error removing policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "PUT":
		var group control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding policy data to edit new group/s: ", err)
			return
		}

		if err := ctrl.EditPolicies(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error editing policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "POST":
		var policy control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&policy)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to add new group: ", err)
			return
		}

		if err := ctrl.AddPolicy(policy); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error adding policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	default:
		http.NotFound(w, r)
		return
	}

}
