package adminui

import (
	"encoding/json"
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
	var newNodeReq data.NewNodeRequest
	err := json.NewDecoder(r.Body).Decode(&newNodeReq)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := data.AddMember(newNodeReq.NodeName, newNodeReq.ConnectionURL, newNodeReq.ManagerURL)
	if err != nil {
		log.Println("failed to add member: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	newNodeResp := data.NewNodeResponse{
		JoinToken: token,
	}
	b, _ := json.Marshal(newNodeResp)

	log.Println("added new node: ", newNodeReq.NodeName, newNodeReq.ConnectionURL)

	w.Write(b)
}

func (au *AdminUI) getClusterEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	events := data.EventsQueue.ReadAll()

	var (
		es  EventsResponseDTO
		err error
	)
	es.EventLog = events
	es.Errors, err = data.GetAllErrors()
	if err != nil {
		var e GenericFailureResponseDTO
		e.Message = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(e)

		return
	}

	json.NewEncoder(w).Encode(es)
}

func (au *AdminUI) nodeControl(w http.ResponseWriter, r *http.Request) {
	var ncR data.NodeControlRequest
	err := json.NewDecoder(r.Body).Decode(&ncR)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	switch ncR.Action {
	case "promote":
		log.Println("promoting node ", ncR.Node)

		err = data.PromoteMember(ncR.Node)
		if err != nil {
			log.Println("failed to promote member: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "drain", "restore":
		log.Println(ncR.Action, "node", ncR.Node)
		// Doesnt do anything to the node itself, just marks it as unhealthy so load balancers will no longer direct clients its way.
		err = data.SetDrained(ncR.Node, ncR.Action == "drain")
		if err != nil {
			log.Println("failed to set/reset node drain: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "stepdown":
		log.Println("node instructed to step down from leadership")
		err = data.StepDown()
		if err != nil {
			log.Println("failed to step down from leadership makenode: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "remove":

		log.Println("attempting to remove node ", ncR.Node)

		if data.GetServerID().String() == ncR.Node {
			log.Println("user tried to remove current operating node from cluster")
			http.Error(w, "cannot remove current node", http.StatusBadRequest)
			return
		}

		err = data.RemoveMember(ncR.Node)
		if err != nil {
			log.Println("failed to remove member from cluster: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	w.Write([]byte("OK"))

}

func (au *AdminUI) clusterEventsAcknowledge(w http.ResponseWriter, r *http.Request) {

	var acknowledgeError struct {
		ErrorID string
	}
	err := json.NewDecoder(r.Body).Decode(&acknowledgeError)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err = data.ResolveError(acknowledgeError.ErrorID)
	if err != nil {
		log.Println("failed to resolve error: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Write([]byte("Success!"))
}
