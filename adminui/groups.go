package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/pkg/control"
)

func (au *AdminUI) getAllGroups(w http.ResponseWriter, r *http.Request) {
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
}
func (au *AdminUI) editGroup(w http.ResponseWriter, r *http.Request) {
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
}
func (au *AdminUI) createGroup(w http.ResponseWriter, r *http.Request) {
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
}
func (au *AdminUI) deleteGroups(w http.ResponseWriter, r *http.Request) {
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
}
