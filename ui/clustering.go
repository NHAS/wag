package ui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

func clusteringUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := struct {
		Page
		Members     []*membership.Member
		Leader      types.ID
		CurrentNode string
	}{
		Page: Page{
			Notification: getUpdate(),
			Description:  "Clustering Management Page",
			Title:        "Clustering",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},
		Members:     data.GetMembers(),
		Leader:      data.GetLeader(),
		CurrentNode: data.GetServerID(),
	}

	err := renderDefaults(w, r, d, "management/cluster.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render clustering page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func newNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var newNodeReq data.NewNodeRequest
	err := json.NewDecoder(r.Body).Decode(&newNodeReq)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if newNodeReq.ManagerURL == "" {
		newNodeReq.ManagerURL = "https://localhost:4545"
	}

	token, err := data.AddMember(newNodeReq.NodeName, newNodeReq.ConnectionURL, newNodeReq.ManagerURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
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
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	var ncR data.NodeControlRequest
	err := json.NewDecoder(r.Body).Decode(&ncR)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	switch ncR.Action {
	case "promote":
	case "drain":
	case "remove":
		if data.GetServerID() == ncR.Node {
			http.Error(w, "cannot remove current node", http.StatusBadRequest)

			return
		}

		err = data.RemoveMember(ncR.Node)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	w.Write([]byte("OK"))

}
