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

	"github.com/NHAS/wag/internal/router"
)

func (au *AdminUI) firewallDiagnositicsUI(w http.ResponseWriter, r *http.Request) {
	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	rules, err := au.ctrl.FirewallRules()
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
		State string
	}{
		Page: Page{

			Description: "Firewall state page",
			Title:       "Firewall",
		},
		State: string(result),
	}

	err = au.renderDefaults(w, r, d, "diagnostics/firewall_state.html")

	if err != nil {
		log.Println("unable to render firewall page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}
}

func (au *AdminUI) wgDiagnositicsUI(w http.ResponseWriter, r *http.Request) {
	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description: "Wireguard Devices",
		Title:       "wg",
	}

	au.renderDefaults(w, r, d, "diagnostics/wireguard_peers.html")
}

func (au *AdminUI) wgDiagnositicsData(w http.ResponseWriter, r *http.Request) {
	peers, err := au.firewall.ListPeers()
	if err != nil {
		log.Println("unable to list wg peers: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var wireguardPeers []WgDevicesData

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
	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	var (
		username string
		acl      string
	)
	if r.Method == http.MethodPost {

		username = r.PostFormValue("username")
		acls, err := au.ctrl.GetUsersAcls(username)
		if err == nil {
			b, _ := json.MarshalIndent(acls, "", "    ")
			acl = string(b)
		} else {
			acl = err.Error()
		}
	}

	d := struct {
		Page
		AclString string
		Username  string
	}{
		Page: Page{

			Description: "ACL Checker",
			Title:       "ACLs",
		},
		AclString: acl,
		Username:  username,
	}

	au.renderDefaults(w, r, d, "diagnostics/acl_tester.html")
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
		checkerDecision, err := router.CheckRoute(address, targetIP, proto, port)
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
