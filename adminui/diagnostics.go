package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (au *AdminUI) getFirewallState(w http.ResponseWriter, r *http.Request) {

	rules, err := au.ctrl.FirewallRules()
	if err != nil {
		log.Println("error getting firewall rules data", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")

	err = json.NewEncoder(w).Encode(rules)
	if err != nil {
		log.Println("error marshalling data", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

}

func (au *AdminUI) wgDiagnositicsData(w http.ResponseWriter, r *http.Request) {
	peers, err := au.firewall.ListPeers()
	if err != nil {
		log.Println("unable to list wg peers: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	result, err := json.Marshal(wireguardPeers)
	if err != nil {
		log.Println("unable to marshal peers data: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(result)

}

func (au *AdminUI) aclsTest(w http.ResponseWriter, r *http.Request) {

	var req AclsTestRequestDTO
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Println("decoding json failed: ", err)
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	acls, err := au.ctrl.GetUsersAcls(req.Username)

	var resp AclsTestResponseDTO
	if err != nil {
		resp.Message = fmt.Sprintf("failed to test: %s", err)
	} else {
		resp.Acls = &acls
	}

	json.NewEncoder(w).Encode(resp)
}

func (au *AdminUI) firewallCheckTest(w http.ResponseWriter, r *http.Request) {
	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	var inputErrors []error
	address := r.FormValue("address")
	if net.ParseIP(address) == nil {
		inputErrors = append(inputErrors, fmt.Errorf("device (%s) not an ip address", address))
	}

	target := r.FormValue("target")
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		addresses, err := net.LookupIP(target)
		if err != nil {
			inputErrors = append(inputErrors, fmt.Errorf("could not lookup %s, err: %s", target, err))
		} else {
			if len(addresses) == 0 {
				inputErrors = append(inputErrors, fmt.Errorf("no addresses for %s", target))
			} else {
				targetIP = addresses[0]
			}
		}
	}

	proto := r.FormValue("protocol")
	port := 0
	if r.FormValue("port") != "" {
		var err error
		port, err = strconv.Atoi(r.FormValue("port"))
		if err != nil {
			inputErrors = append(inputErrors, fmt.Errorf("could not parse port: %s", err))
		}
	}

	var decision string
	if len(inputErrors) == 0 {
		checkerDecision, err := au.firewall.CheckRoute(address, targetIP, proto, port)
		if err != nil {
			decision = err.Error()
		} else {

			isAuthed := "(unauthorised)"
			if au.firewall.IsAuthed(address) {
				isAuthed = "(authorised)"
			}

			displayProto := fmt.Sprintf("%d/%s", port, proto)
			if proto == "icmp" {
				displayProto = proto
			}
			decision = fmt.Sprintf("%s -%s-> %s, decided: %s %s", address, displayProto, target, checkerDecision, isAuthed)
		}

	} else {
		decision = errors.Join(inputErrors...).Error()
	}

	d := struct {
		Page
		Address   string
		Target    string
		Port      int
		Decision  string
		Protocols []struct {
			Val      string
			Name     string
			Selected bool
		}
	}{
		Page: Page{

			Description: "ACL Checker",
			Title:       "ACLs",
		},
		Decision: decision,
		Address:  address,
		Port:     port,
		Target:   target,
	}

	d.Protocols = []struct {
		Val      string
		Name     string
		Selected bool
	}{
		{Val: "tcp", Name: "TCP", Selected: proto == "tcp"},
		{Val: "udp", Name: "UDP", Selected: proto == "udp"},
		{Val: "icmp", Name: "ICMP", Selected: proto == "icmp"},
	}

	au.renderDefaults(w, r, d, "diagnostics/route_checker.html")
}
