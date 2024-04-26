package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/wag/internal/router"
)

func firewallDiagnositicsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	rules, err := ctrl.FirewallRules()
	if err != nil {
		log.Println("error getting firewall rules data", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := json.MarshalIndent(rules, "", "    ")
	if err != nil {
		log.Println("error marshalling data", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	d := struct {
		Page
		XDPState string
	}{
		Page: Page{
			Notification: getUpdate(),
			Description:  "Firewall state page",
			Title:        "Firewall",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},
		XDPState: string(result),
	}

	err = renderDefaults(w, r, d, "diagnostics/firewall_state.html")

	if err != nil {
		log.Println("unable to render firewall page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func wgDiagnositicsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{
		Notification: getUpdate(),
		Description:  "Wireguard Devices",
		Title:        "wg",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	renderDefaults(w, r, d, "diagnostics/wireguard_peers.html")
}

func wgDiagnositicsData(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	peers, err := router.ListPeers()
	if err != nil {
		log.Println("unable to list wg peers: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := []WgDevicesData{}

	for _, peer := range peers {
		ip := "-"
		if len(peer.AllowedIPs) > 0 {
			ip = peer.AllowedIPs[0].String()
		}

		data = append(data, WgDevicesData{

			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,

			PublicKey:         peer.PublicKey.String(),
			Address:           ip,
			EndpointAddress:   peer.Endpoint.String(),
			LastHandshakeTime: peer.LastHandshakeTime.Format(time.RFC1123),
		})
	}

	result, err := json.Marshal(data)
	if err != nil {
		log.Println("unable to marshal peers data: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)

}
