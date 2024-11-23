package adminui

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (au *AdminUI) getFirewallState(w http.ResponseWriter, r *http.Request) {

	rules, err := au.ctrl.FirewallRules()
	if err != nil {
		log.Println("error getting firewall rules data", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (au *AdminUI) wgDiagnositicsData(w http.ResponseWriter, r *http.Request) {

	var (
		peers []wgtypes.Peer
		err   error
	)
	defer func() {
		if err != nil {
			au.respond(err, w)
		}
	}()

	peers, err = au.firewall.ListPeers()
	if err != nil {
		log.Println("unable to list wg peers: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	wireguardPeers := []WgDevicesData{}

	for _, peer := range peers {
		ip := "-"
		if len(peer.AllowedIPs) > 0 {
			ip = peer.AllowedIPs[0].String()
		}

		wireguardPeers = append(wireguardPeers, WgDevicesData{

			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,

			PublicKey:         peer.PublicKey.String(),
			Address:           ip,
			EndpointAddress:   peer.Endpoint.String(),
			LastHandshakeTime: peer.LastHandshakeTime.Format(time.RFC1123),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wireguardPeers)
}

func (au *AdminUI) aclsTest(w http.ResponseWriter, r *http.Request) {

	var (
		resp AclsTestResponseDTO
		req  AclsTestRequestDTO

		err error
	)
	defer func() {
		if err != nil {
			au.respond(err, w)
		}
	}()

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println("decoding json failed: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	resp.Acls, err = au.ctrl.GetUsersAcls(req.Username)
	if err != nil {
		resp.Message = fmt.Sprintf("failed fetch user acls: %s", err)
	} else {
		resp.Success = true
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (au *AdminUI) firewallCheckTest(w http.ResponseWriter, r *http.Request) {

	var (
		err      error
		t        FirewallTestRequestDTO
		decision string
	)

	defer func() { au.respondSuccess(err, decision, w) }()

	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = t.Validate()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	checkerDecision, err := au.firewall.CheckRoute(t.Address, net.ParseIP(t.Target), t.Protocol, t.Port)
	if err != nil {
		decision = err.Error()
	} else {

		isAuthed := "(unauthorised)"
		if au.firewall.IsAuthed(t.Address) {
			isAuthed = "(authorised)"
		}

		displayProto := fmt.Sprintf("%d/%s", t.Port, t.Protocol)
		if t.Protocol == "icmp" {
			displayProto = t.Protocol
		}
		decision = fmt.Sprintf("%s -%s-> %s, decided: %s %s", t.Address, displayProto, t.Target, checkerDecision, isAuthed)
	}
}
