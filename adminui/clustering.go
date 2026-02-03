package adminui

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) members(w http.ResponseWriter, r *http.Request) {
	var members []MembershipDTO
	for _, member := range au.db.GetClusterMembers() {
		drained, err := au.db.IsClusterNodeDrained(member.ID.String())
		if err != nil {
			log.Error().Err(err).Msg("unable to get node state")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		witness, err := au.db.IsClusterNodeWitness(member.ID.String())
		if err != nil {
			log.Error().Err(err).Msg("unable to witness state")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		version, err := au.db.GetClusterNodeVersion(member.ID.String())
		if err != nil {
			log.Error().Err(err).Msg("unable to get version")
			version = "unknown"
		}

		status := "healthy" // full liveness
		if drained {
			status = "drained"
		} else if !member.IsStarted() {
			status = "wait for first connection..."
		} else if member.IsLearner {
			status = "learner"
		}

		ping := ""
		if status != "learner" {
			lastPing, err := au.db.GetClusterNodeLastPing(member.ID.String())
			if err != nil {
				log.Warn().Err(err).Str("node", member.ID.String()).Msg("unable to fetch node last ping")
				status = "no last ping"
			} else {

				if lastPing.Before(time.Now().Add(-30 * time.Second)) {
					status += "(lagging ping)"
				}

				if lastPing.Before(time.Now().Add(-60 * time.Second)) {
					status = "dead"
				}

				ping = lastPing.Format(time.RFC822)
			}
		}

		members = append(members, MembershipDTO{
			ID:            member.ID.String(),
			PeerUrls:      member.PeerURLs,
			Name:          member.Name,
			IsLearner:     member.IsLearner,
			IsDrained:     drained,
			IsWitness:     witness,
			IsCurrentNode: au.db.GetCurrentNodeID() == member.ID,
			IsLeader:      au.db.GetClusterLeader() == member.ID,
			Status:        status,
			Ping:          ping,
			Version:       version,
		})

	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(members)
}

func (au *AdminUI) newNode(w http.ResponseWriter, r *http.Request) {
	var (
		newNodeReq  NewNodeRequestDTO
		newNodeResp NewNodeResponseDTO
		err         error
	)

	defer func() {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			newNodeResp.ErrorMessage = err.Error()
		}
		json.NewEncoder(w).Encode(newNodeResp)
	}()

	err = safedecoder.Decoder(r.Body).Decode(&newNodeReq)
	if err != nil {
		log.Warn().Err(err).Msg("failed to json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	newNodeResp.JoinToken, err = au.db.AddClusterMember(newNodeReq.NodeName, newNodeReq.ConnectionURL, newNodeReq.ManagerURL)
	if err != nil {
		log.Error().Err(err).Str("node_name", newNodeReq.NodeName).Str("url", newNodeReq.ConnectionURL).Msg("failed to add member node")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Info().Str("node_name", newNodeReq.NodeName).Str("url", newNodeReq.ConnectionURL).Msg("new node added")
}

func (au *AdminUI) getClusterEvents(w http.ResponseWriter, r *http.Request) {

	var (
		es = EventsResponseDTO{
			EventLog: au.db.GetEventQueue(),
		}
		err error
	)
	defer func() {
		if err != nil {
			au.respond(err, w)
		}
	}()

	es.Errors, err = au.db.GetAllErrors()
	if err != nil {
		log.Error().Err(err).Msg("failed to get cluster errors")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(es)
}

func (au *AdminUI) nodeControl(w http.ResponseWriter, r *http.Request) {
	var (
		ncR NodeControlRequestDTO
		err error
	)

	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&ncR)
	if err != nil {
		log.Warn().Err(err).Msg("failed to json body")

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch ncR.Action {
	case "promote":

		err = au.db.PromoteClusterMember(ncR.Node)
		if err != nil {
			log.Error().Err(err).Str("node", ncR.Node).Msg("failed to promote node")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Info().Str("node", ncR.Node).Msg("node promoted to full member")

	case "drain", "restore":
		// Doesnt do anything to the node itself, just marks it as unhealthy so load balancers will no longer direct clients its way.
		err = au.db.SetDrained(ncR.Node, ncR.Action == "drain")
		if err != nil {
			log.Error().Err(err).Str("node", ncR.Node).Str("action", ncR.Action).Msg("failed")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Info().Str("node", ncR.Node).Str("action", ncR.Action).Msg("succeeded")

	case "stepdown":
		err = au.db.ClusterNodeStepDown()
		if err != nil {
			log.Error().Err(err).Str("node", ncR.Node).Msg("failed to make node step down from leadership")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Info().Str("node", ncR.Node).Msg("node instructed to step down from leadership")

	case "remove":

		if au.db.GetCurrentNodeID().String() == ncR.Node {
			log.Error().Err(err).Str("node", ncR.Node).Msg("user tried to remove current operating node from cluster")

			err = errors.New("cannot remove current node")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		err = au.db.RemoveClusterMember(ncR.Node)
		if err != nil {
			log.Error().Err(err).Str("node", ncR.Node).Msg("unable to remove node from cluster")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Info().Str("node", ncR.Node).Msg("node removed from cluster")

	default:
		err = errors.New("unknown action")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func (au *AdminUI) clusterEventsAcknowledge(w http.ResponseWriter, r *http.Request) {

	var (
		acknowledgeError AcknowledgeErrorResponseDTO
		err              error
	)

	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&acknowledgeError)
	if err != nil {
		log.Warn().Err(err).Msg("failed to json body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.db.ResolveError(acknowledgeError.ErrorID)
	if err != nil {
		log.Error().Err(err).Str("wag_error_id", acknowledgeError.ErrorID).Msg("failed to acknowledge wag error")
		w.WriteHeader(http.StatusInternalServerError)
	}

	log.Info().Err(err).Str("wag_error_id", acknowledgeError.ErrorID).Msg("wag error acknowledged & cleared")

}
