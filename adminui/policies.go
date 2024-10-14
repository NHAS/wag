package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
)

func (au *AdminUI) policiesUI(w http.ResponseWriter, r *http.Request) {

	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}
	d := Page{

		Description: "Firewall rules",
		Title:       "Rules",
	}

	err := au.renderDefaults(w, r, d, "policy/rules.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render rules page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}
}

func (au *AdminUI) policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := au.ctrl.GetPolicies()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println("unable to get policies: ", err)
			return
		}

		b, err := json.Marshal(data)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("unable to marshal policies data: ", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var policiesToRemove []string
		err := json.NewDecoder(r.Body).Decode(&policiesToRemove)
		if err != nil {
			log.Println("error decoding policy names to remove: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)

			return
		}

		if err := au.ctrl.RemovePolicies(policiesToRemove); err != nil {
			log.Println("error removing policy: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return
	case "PUT":
		var group control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			log.Println("error decoding policy data to edit new group/s: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)

			return
		}

		if err := au.ctrl.EditPolicies(group); err != nil {
			log.Println("error editing policy: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Write([]byte("OK"))
		return
	case "POST":
		var policy control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&policy)
		if err != nil {
			log.Println("error decoding group data to add new group: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)

			return
		}

		if err := au.ctrl.AddPolicy(policy); err != nil {
			log.Println("error adding policy: ", err)
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		w.Write([]byte("OK"))
		return
	default:
		http.NotFound(w, r)
		return
	}

}
