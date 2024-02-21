package ui

import (
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

	err := renderDefaults(w, r, d, "settings/clustering.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render clustering page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}
