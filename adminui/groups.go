package adminui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) getAllGroups(w http.ResponseWriter, r *http.Request) {

	data, err := au.ctrl.GetGroups()
	if err != nil {
		log.Error().Err(err).Msg("unable to get group data")
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
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.EditGroup(group)
	if err != nil {
		log.Error().Err(err).Str("group", group.Group).Msg("error editing group")

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
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.AddGroup(group)
	if err != nil {
		log.Error().Err(err).Str("group", group.Group).Msg("error creating group")
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
		log.Error().Err(err).Msg("failed to parse json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.ctrl.RemoveGroup(groupsToRemove)
	if err != nil {
		log.Error().Err(err).Str("groups", strings.Join(groupsToRemove, ",")).Msg("error removing group/s")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
