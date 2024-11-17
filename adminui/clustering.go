package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

type MembershipDTO struct {
	*membership.Member
	IsDrained bool
	IsWitness bool

	Version string
	Ping    string
	Status  string
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
