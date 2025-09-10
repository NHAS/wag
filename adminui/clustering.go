package adminui

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) members(w http.ResponseWriter, r *http.Request) {
	var members []MembershipDTO
	for _, member := range au.db.GetClusterMembers() {
		drained, err := au.db.IsClusterNodeDrained(member.ID.String())
		if err != nil {
			log.Println("unable to get drained state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		witness, err := au.db.IsClusterNodeWitness(member.ID.String())
		if err != nil {
			log.Println("unable to witness state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		version, err := au.db.GetClusterNodeVersion(member.ID.String())
		if err != nil {
			log.Println("unable to get version: ", err)
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
				log.Println("unable to fetch last ping: ", err)
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
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	newNodeResp.JoinToken, err = au.db.AddClusterMember(newNodeReq.NodeName, newNodeReq.ConnectionURL, newNodeReq.ManagerURL)
	if err != nil {
		log.Println("failed to add member: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("added new node: ", newNodeReq.NodeName, newNodeReq.ConnectionURL)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch ncR.Action {
	case "promote":
		log.Println("promoting node ", ncR.Node)

		err = au.db.PromoteClusterMember(ncR.Node)
		if err != nil {
			log.Println("failed to promote member: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "drain", "restore":
		log.Println(ncR.Action, "node", ncR.Node)
		// Doesnt do anything to the node itself, just marks it as unhealthy so load balancers will no longer direct clients its way.
		err = au.db.SetDrained(ncR.Node, ncR.Action == "drain")
		if err != nil {
			log.Println("failed to set/reset node drain: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "stepdown":
		log.Println("node instructed to step down from leadership")
		err = au.db.ClusterNodeStepDown()
		if err != nil {
			log.Println("failed to step down from leadership makenode: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "remove":

		log.Println("attempting to remove node ", ncR.Node)

		if au.db.GetCurrentNodeID().String() == ncR.Node {
			log.Println("user tried to remove current operating node from cluster")
			err = errors.New("cannot remove current node")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		err = au.db.RemoveClusterMember(ncR.Node)
		if err != nil {
			log.Println("failed to remove member from cluster: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.db.ResolveError(acknowledgeError.ErrorID)
	if err != nil {
		log.Println("failed to resolve error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
