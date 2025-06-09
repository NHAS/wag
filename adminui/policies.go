package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) getAllPolicies(w http.ResponseWriter, r *http.Request) {
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
}

func (au *AdminUI) editPolicy(w http.ResponseWriter, r *http.Request) {
	var (
		group control.PolicyData
		err   error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&group)
	if err != nil {
		log.Println("error decoding policy data to edit new group/s: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.EditPolicies(group)
	if err != nil {
		log.Println("error editing policy: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
func (au *AdminUI) createPolicy(w http.ResponseWriter, r *http.Request) {
	var (
		policy control.PolicyData
		err    error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&policy)
	if err != nil {
		log.Println("error decoding group data to add new group: ", err)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if err = au.ctrl.AddPolicy(policy); err != nil {
		log.Println("error adding policy: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}
}

func (au *AdminUI) deletePolices(w http.ResponseWriter, r *http.Request) {
	var (
		err              error
		policiesToRemove []string
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&policiesToRemove)
	if err != nil {
		log.Println("error decoding policy names to remove: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = au.ctrl.RemovePolicies(policiesToRemove); err != nil {
		log.Println("error removing policy: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
