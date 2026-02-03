package server

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (wsg *WagControlSocketServer) policies(w http.ResponseWriter, r *http.Request) {
	policies, err := wsg.db.GetPolicies()
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

	if err := safedecoder.Decoder(r.Body).Decode(&acl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if err := wsg.db.SetAcl(acl.Effects, acls.Acl{Mfa: acl.MfaRoutes, Allow: acl.PublicRoutes, Deny: acl.DenyRoutes}, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Str("policy", acl.Effects).Str("action", "created").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) editPolicy(w http.ResponseWriter, r *http.Request) {

	var polciyData control.PolicyData

	if err := safedecoder.Decoder(r.Body).Decode(&polciyData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := wsg.db.SetAcl(polciyData.Effects, acls.Acl{Mfa: polciyData.MfaRoutes, Allow: polciyData.PublicRoutes, Deny: polciyData.DenyRoutes}, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Str("policy", polciyData.Effects).Str("action", "edited").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) deletePolicies(w http.ResponseWriter, r *http.Request) {
	var policyNames []string
	if err := safedecoder.Decoder(r.Body).Decode(&policyNames); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	for _, policyName := range policyNames {
		if err := wsg.db.RemoveAcl(policyName); err != nil {
			log.Error().Err(err).Str("policy", policyName).Msg("unable to set remove policy")

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	log.Info().Strs("policy", policyNames).Str("action", "deleted").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) groups(w http.ResponseWriter, r *http.Request) {
	groups, err := wsg.db.GetGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, _ := json.Marshal(groups)

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (wsg *WagControlSocketServer) newGroup(w http.ResponseWriter, r *http.Request) {

	var gData control.GroupCreateData

	if err := safedecoder.Decoder(r.Body).Decode(&gData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if err := wsg.db.CreateGroup(gData.Group, gData.AddedMembers); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Str("group", gData.Group).Strs("added_members", gData.AddedMembers).Str("action", "added").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) editGroup(w http.ResponseWriter, r *http.Request) {

	var gdata control.GroupEditData

	if err := safedecoder.Decoder(r.Body).Decode(&gdata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := wsg.db.RemoveUserFromGroup(gdata.RemovedMembers, gdata.Group); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := wsg.db.AddUserToGroups(gdata.AddedMembers, []string{gdata.Group}, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Str("group", gdata.Group).Strs("added_members", gdata.AddedMembers).Strs("removed_members", gdata.RemovedMembers).Str("action", "edited").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) deleteGroup(w http.ResponseWriter, r *http.Request) {

	var groupNames []string
	if err := safedecoder.Decoder(r.Body).Decode(&groupNames); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	for _, groupName := range groupNames {
		if err := wsg.db.RemoveGroup(groupName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	log.Info().Strs("group", groupNames).Str("action", "deleted").Send()

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) getDBKey(w http.ResponseWriter, r *http.Request) {

	var key string

	if err := safedecoder.Decoder(r.Body).Decode(&key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if key == "" {
		http.Error(w, "No key specified", http.StatusInternalServerError)
		return
	}

	log.Info().Str("get", key).Str("action", "get etcd key").Send()

	data, err := wsg.db.Get(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(data)
}

func (wsg *WagControlSocketServer) putDBKey(w http.ResponseWriter, r *http.Request) {

	var toWrite control.PutReq

	if err := safedecoder.Decoder(r.Body).Decode(&toWrite); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if toWrite.Key == "" {
		http.Error(w, "No key specified", http.StatusInternalServerError)
		return
	}

	log.Info().Str("put", toWrite.Key).Str("action", "put etcd key").Send()

	err := wsg.db.Put(toWrite.Key, toWrite.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
}
