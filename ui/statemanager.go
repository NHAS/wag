package ui

import "github.com/NHAS/wag/internal/data"

var (
	clusterState string
	serverID     string
)

func watchClusterHealth(state string) {
	clusterState = state
	serverID = data.GetServerID().String()
}
