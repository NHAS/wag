package adminui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) getAllPolicies(w http.ResponseWriter, r *http.Request) {
	data, err := au.ctrl.GetPolicies()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("unable to get policies")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (au *AdminUI) editPolicy(w http.ResponseWriter, r *http.Request) {
	var (
		policy control.PolicyData
		err    error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&policy)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.EditPolicies(policy)
	if err != nil {
		log.Error().Err(err).Str("policy", policy.Effects).Msg("failed to apply policy change")
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
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if err = au.ctrl.AddPolicy(policy); err != nil {
		log.Error().Err(err).Str("policy", policy.Effects).Msg("failed to create new policy")
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
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = au.ctrl.RemovePolicies(policiesToRemove); err != nil {
		log.Error().Err(err).Str("policies", strings.Join(policiesToRemove, ", ")).Msg("remove policies")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
