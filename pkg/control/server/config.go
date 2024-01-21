package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
)

func policies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	policies, err := data.GetPolicies()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	resultBytes, _ := json.Marshal(policies)

	w.Header().Set("Content-Type", "application/json")
	w.Write(resultBytes)
}

func newPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var acl control.PolicyData

	if err := json.NewDecoder(r.Body).Decode(&acl); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := data.SetAcl(acl.Effects, acls.Acl{Mfa: acl.MfaRoutes, Allow: acl.PublicRoutes}, false); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("new policy '%s' added", acl.Effects)

	w.Write([]byte("OK!"))
}

func editPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var polciyData control.PolicyData

	if err := json.NewDecoder(r.Body).Decode(&polciyData); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := data.SetAcl(polciyData.Effects, acls.Acl{Mfa: polciyData.MfaRoutes, Allow: polciyData.PublicRoutes}, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("policy '%s' edited", polciyData.Effects)

	w.Write([]byte("OK!"))
}

func deletePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var policyNames []string
	if err := json.NewDecoder(r.Body).Decode(&policyNames); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	for _, policyName := range policyNames {
		if err := data.RemoveAcl(policyName); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	log.Printf("policy '%s' deleted", policyNames)

	w.Write([]byte("OK!"))
}

func groups(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	groups, err := data.GetGroups()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	result, _ := json.Marshal(groups)

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func newGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var gData control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&gData); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := data.SetGroup(gData.Group, gData.Members, false); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("new group '%s' added", gData.Group)

	w.Write([]byte("OK!"))
}

func editGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var gdata control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&gdata); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := data.SetGroup(gdata.Group, gdata.Members, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("group '%s' edited", gdata.Group)

	w.Write([]byte("OK!"))
}

func deleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var groupNames []string
	if err := json.NewDecoder(r.Body).Decode(&groupNames); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	for _, groupName := range groupNames {
		if err := data.RemoveGroup(groupName); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	log.Printf("group/s '%s' deleted", groupNames)

	w.Write([]byte("OK!"))
}
