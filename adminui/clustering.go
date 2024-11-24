package adminui

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/wag/internal/data"
)

func (au *AdminUI) members(w http.ResponseWriter, r *http.Request) {
	var members []MembershipDTO
	for _, member := range data.GetMembers() {
		drained, err := data.IsDrained(member.ID.String())
		if err != nil {
			log.Println("unable to get drained state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		witness, err := data.IsWitness(member.ID.String())
		if err != nil {
			log.Println("unable to witness state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		version, err := data.GetVersion(member.ID.String())
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
			lastPing, err := data.GetLastPing(member.ID.String())
			if err != nil {
				log.Println("unable to fetch last ping: ", err)
				status = "no last ping"
			} else {

				if lastPing.Before(time.Now().Add(-6 * time.Second)) {
					status += "(lagging ping)"
				}

				if lastPing.Before(time.Now().Add(-14 * time.Second)) {
					status = "dead"
				}

				ping = lastPing.Format(time.RFC822)
			}
		}

		members = append(members, MembershipDTO{
			ID:            member.ID,
			PeerUrls:      member.PeerURLs,
			Name:          member.Name,
			IsLearner:     member.IsLearner,
			IsDrained:     drained,
			IsWitness:     witness,
			IsCurrentNode: data.GetServerID() == member.ID,
			IsLeader:      data.GetLeader() == member.ID,
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
	)

	defer func() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(newNodeResp)
	}()

	newNodeResp.ErrorMessage = json.NewDecoder(r.Body).Decode(&newNodeReq)
	if newNodeResp.ErrorMessage != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	newNodeResp.JoinToken, newNodeResp.ErrorMessage = data.AddMember(newNodeReq.NodeName, newNodeReq.ConnectionURL, newNodeReq.ManagerURL)
	if newNodeResp.ErrorMessage != nil {
		log.Println("failed to add member: ", newNodeResp.ErrorMessage)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("added new node: ", newNodeReq.NodeName, newNodeReq.ConnectionURL)
}

func (au *AdminUI) getClusterEvents(w http.ResponseWriter, r *http.Request) {

	var (
		es = EventsResponseDTO{
			EventLog: data.EventsQueue.ReadAll(),
		}
		err error
	)
	defer func() {
		if err != nil {
			au.respond(err, w)
		}
	}()

	es.Errors, err = data.GetAllErrors()
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

	err = json.NewDecoder(r.Body).Decode(&ncR)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch ncR.Action {
	case "promote":
		log.Println("promoting node ", ncR.Node)

		err = data.PromoteMember(ncR.Node)
		if err != nil {
			log.Println("failed to promote member: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "drain", "restore":
		log.Println(ncR.Action, "node", ncR.Node)
		// Doesnt do anything to the node itself, just marks it as unhealthy so load balancers will no longer direct clients its way.
		err = data.SetDrained(ncR.Node, ncR.Action == "drain")
		if err != nil {
			log.Println("failed to set/reset node drain: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "stepdown":
		log.Println("node instructed to step down from leadership")
		err = data.StepDown()
		if err != nil {
			log.Println("failed to step down from leadership makenode: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "remove":

		log.Println("attempting to remove node ", ncR.Node)

		if data.GetServerID().String() == ncR.Node {
			log.Println("user tried to remove current operating node from cluster")
			err = errors.New("cannot remove current node")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		err = data.RemoveMember(ncR.Node)
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

	err = json.NewDecoder(r.Body).Decode(&acknowledgeError)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.ResolveError(acknowledgeError.ErrorID)
	if err != nil {
		log.Println("failed to resolve error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
