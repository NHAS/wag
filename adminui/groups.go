package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) getAllGroups(w http.ResponseWriter, r *http.Request) {

	data, err := au.ctrl.GetGroups()
	if err != nil {
		log.Println("unable to get group data from server: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (au *AdminUI) editGroup(w http.ResponseWriter, r *http.Request) {
	var (
		group control.GroupEditData
		err   error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&group)
	if err != nil {
		log.Println("error decoding group data to edit new group/s: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.EditGroup(group)
	if err != nil {
		log.Println("error editing group: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) createGroup(w http.ResponseWriter, r *http.Request) {
	var (
		group control.GroupCreateData
		err   error
	)

	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&group)
	if err != nil {
		log.Println("error decoding group data to add new group: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.AddGroup(group)
	if err != nil {
		log.Println("error adding group: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) deleteGroups(w http.ResponseWriter, r *http.Request) {
	var (
		groupsToRemove []string
		err            error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&groupsToRemove)
	if err != nil {
		log.Println("error decoding group names to remove: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.RemoveGroup(groupsToRemove)
	if err != nil {
		log.Println("error removing groups: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
