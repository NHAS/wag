package adminui

import "github.com/NHAS/wag/internal/data"

func (au *AdminUI) watchClusterHealth(state string) {
	au.clusterState = state
	au.serverID = data.GetServerID().String()
}
