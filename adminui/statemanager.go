package adminui

func (au *AdminUI) watchClusterHealth(state string) {
	au.clusterState = state
	au.serverID = au.db.GetCurrentNodeID().String()
}
