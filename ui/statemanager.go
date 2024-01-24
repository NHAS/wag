package ui

import "github.com/NHAS/wag/internal/data"

var (
	clusterState string
	serverID     string
)

func watchClusterHealth(state string, _ int) {
	clusterState = state
	serverID = data.GetServerID()
}
