package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/wag/internal/data"
	"go.etcd.io/etcd/client/pkg/v3/types"
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

func clusterMembersUI(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := struct {
		Page
		Members     []MembershipDTO
		Leader      types.ID
		CurrentNode string
	}{
		Page: Page{

			Description:  "Clustering Management Page",
			Title:        "Clustering",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},

		Leader:      data.GetLeader(),
		CurrentNode: data.GetServerID().String(),
	}

	members := data.GetMembers()
	for i := range data.GetMembers() {
		drained, err := data.IsDrained(members[i].ID.String())
		if err != nil {
			log.Println("unable to get drained state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		witness, err := data.IsWitness(members[i].ID.String())
		if err != nil {
			log.Println("unable to witness state: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		version, err := data.GetVersion(members[i].ID.String())
		if err != nil {
			log.Println("unable to get version: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := "healthy" // full liveness
		if drained {
			status = "drained"
		} else if !members[i].IsStarted() {
			status = "wait for first connection..."
		} else if members[i].IsLearner {
			status = "learner"
		}

		ping := ""
		if status != "learner" {
			lastPing, err := data.GetLastPing(members[i].ID.String())
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

		d.Members = append(d.Members, MembershipDTO{
			Member:    members[i],
			IsDrained: drained,
			IsWitness: witness,
			Status:    status,
			Ping:      ping,
			Version:   version,
		})

	}

	err := renderDefaults(w, r, d, "cluster/members.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render clustering page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func newNode(w http.ResponseWriter, r *http.Request) {
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

func nodeControl(w http.ResponseWriter, r *http.Request) {
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

func clusterEventsUI(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := struct {
		Page
		EventLog []string
		Errors   []data.EventError
	}{
		Page: Page{

			Description:  "Clustering Management Page",
			Title:        "Clustering",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},

		EventLog: data.EventsQueue.ReadAll(),
	}

	var err error
	d.Errors, err = data.GetAllErrors()
	if err != nil {
		log.Println("unable to render clustering events page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	err = renderDefaults(w, r, d, "cluster/events.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render clustering events page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func clusterEventsAcknowledge(w http.ResponseWriter, r *http.Request) {

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
