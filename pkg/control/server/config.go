package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control"
)

func aclReload() error {

	errs := router.RefreshConfiguration()
	if len(errs) > 0 {

		return errs[0]
	}

	return nil
}

func configReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := config.Reload()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	errs := router.RefreshConfiguration()
	if len(errs) > 0 {
		w.WriteHeader(500)
		w.Header().Set("Content-Type", "text/plain")
		for _, err := range errs {
			if err != nil {
				w.Write([]byte(err.Error() + "\n"))
			}
		}
		return
	}

	log.Println("Config fully reloaded")

	w.Write([]byte("OK!"))
}

func policies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	data := []control.PolicyData{}

	accessOrder := []string{}
	policies := config.Values().Acls.Policies
	for k := range policies {
		accessOrder = append(accessOrder, k)
	}

	sort.Strings(accessOrder)
	//Stable output for the display or usage, gross because of unordered maps in golang thanks golang
	for _, policyName := range accessOrder {
		data = append(data, control.PolicyData{
			Effects:      policyName,
			PublicRoutes: policies[policyName].Allow,
			MfaRoutes:    policies[policyName].Mfa,
		})
	}

	result, _ := json.Marshal(data)

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
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

	if err := config.AddAcl(acl.Effects, config.Acl{Mfa: acl.MfaRoutes, Allow: acl.PublicRoutes}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if err := aclReload(); err != nil {
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

	var data control.PolicyData

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := config.EditAcl(data.Effects, config.Acl{Mfa: data.MfaRoutes, Allow: data.PublicRoutes}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if err := aclReload(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("policy '%s' edited", data.Effects)

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
		if err := config.DeleteAcl(policyName); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	if err := aclReload(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("policy '%s' deleted", policyNames)

	w.Write([]byte("OK!"))
}

func groups(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	data := []control.GroupData{}

	accessOrder := []string{}
	groups := config.Values().Acls.Groups
	for k := range groups {
		accessOrder = append(accessOrder, k)
	}

	sort.Strings(accessOrder)
	//Stable output for the display or usage, gross because of unordered maps in golang thanks golang
	for _, groupName := range accessOrder {
		data = append(data, control.GroupData{
			Group:   groupName,
			Members: groups[groupName],
		})
	}

	result, _ := json.Marshal(data)

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func newGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var data control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := config.AddGroup(data.Group, data.Members); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if err := aclReload(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("new group '%s' added", data.Group)

	w.Write([]byte("OK!"))
}

func editGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var data control.GroupData

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), 500)
		return

	}

	if err := config.EditGroup(data.Group, data.Members); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if err := aclReload(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("group '%s' edited", data.Group)

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
		if err := config.DeleteGroup(groupName); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	if err := aclReload(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("group/s '%s' deleted", groupNames)

	w.Write([]byte("OK!"))
}
