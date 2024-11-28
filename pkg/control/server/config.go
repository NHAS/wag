package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
)

func (wsg *WagControlSocketServer) policies(w http.ResponseWriter, r *http.Request) {
	policies, err := data.GetPolicies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resultBytes, _ := json.Marshal(policies)

	w.Header().Set("Content-Type", "application/json")
	w.Write(resultBytes)
}

func (wsg *WagControlSocketServer) newPolicy(w http.ResponseWriter, r *http.Request) {

	var acl control.PolicyData

	if err := json.NewDecoder(r.Body).Decode(&acl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if err := data.SetAcl(acl.Effects, acls.Acl{Mfa: acl.MfaRoutes, Allow: acl.PublicRoutes, Deny: acl.DenyRoutes}, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("new policy '%s' added", acl.Effects)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) editPolicy(w http.ResponseWriter, r *http.Request) {

	var polciyData control.PolicyData

	if err := json.NewDecoder(r.Body).Decode(&polciyData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := data.SetAcl(polciyData.Effects, acls.Acl{Mfa: polciyData.MfaRoutes, Allow: polciyData.PublicRoutes, Deny: polciyData.DenyRoutes}, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("policy '%s' edited", polciyData.Effects)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) deletePolicies(w http.ResponseWriter, r *http.Request) {
	var policyNames []string
	if err := json.NewDecoder(r.Body).Decode(&policyNames); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	for _, policyName := range policyNames {
		if err := data.RemoveAcl(policyName); err != nil {
			log.Println("Unable to set remove policy: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	log.Printf("policy '%s' deleted", policyNames)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) groups(w http.ResponseWriter, r *http.Request) {
	groups, err := data.GetGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, _ := json.Marshal(groups)

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (wsg *WagControlSocketServer) newGroup(w http.ResponseWriter, r *http.Request) {

	var gData control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&gData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if err := data.SetGroup(gData.Group, gData.Members, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("new group '%s' added", gData.Group)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) editGroup(w http.ResponseWriter, r *http.Request) {

	var gdata control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&gdata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if err := data.SetGroup(gdata.Group, gdata.Members, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("group '%s' edited", gdata.Group)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) deleteGroup(w http.ResponseWriter, r *http.Request) {

	var groupNames []string
	if err := json.NewDecoder(r.Body).Decode(&groupNames); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	for _, groupName := range groupNames {
		if err := data.RemoveGroup(groupName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	log.Printf("group/s '%s' deleted", groupNames)

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) getDBKey(w http.ResponseWriter, r *http.Request) {

	var key string

	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if key == "" {
		http.Error(w, "No key specified", http.StatusInternalServerError)
		return
	}

	data, err := data.Get(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(data)
}

func (wsg *WagControlSocketServer) putDBKey(w http.ResponseWriter, r *http.Request) {

	var toWrite control.PutReq

	if err := json.NewDecoder(r.Body).Decode(&toWrite); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if toWrite.Key == "" {
		http.Error(w, "No key specified", http.StatusInternalServerError)
		return
	}

	err := data.Put(toWrite.Key, toWrite.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
}
