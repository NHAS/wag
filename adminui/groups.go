package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
)

func (au *AdminUI) groupsUI(w http.ResponseWriter, r *http.Request) {
	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description: "Groups",
		Title:       "Groups",
	}

	err := au.renderDefaults(w, r, d, "policy/groups.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render groups page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}
}

func (au *AdminUI) groups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := au.ctrl.GetGroups()
		if err != nil {
			log.Println("unable to get group data from server: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal groups data: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var groupsToRemove []string
		err := json.NewDecoder(r.Body).Decode(&groupsToRemove)
		if err != nil {
			log.Println("error decoding group names to remove: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := au.ctrl.RemoveGroup(groupsToRemove); err != nil {
			log.Println("error removing groups: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return
	case "PUT":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			log.Println("error decoding group data to edit new group/s: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := au.ctrl.EditGroup(group); err != nil {
			log.Println("error editing group: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return
	case "POST":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			log.Println("error decoding group data to add new group: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)

			return
		}

		if err := au.ctrl.AddGroup(group); err != nil {
			log.Println("error adding group: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Write([]byte("OK"))
		return
	default:
		http.NotFound(w, r)
		return
	}

}
