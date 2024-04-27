package ui

import (
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
)

func populateDashboard(w http.ResponseWriter, r *http.Request) {

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		log.Println("error getting users: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	unenforcedMFA := 0
	for _, u := range allUsers {
		if !u.Enforcing {
			unenforcedMFA++
		}

	}

	allDevices, err := ctrl.ListDevice("")
	if err != nil {
		log.Println("error getting devices: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	lockout, err := data.GetLockout()
	if err != nil {
		log.Println("error getting lockout: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	lockedDevices := 0
	activeSessions := 0
	for _, d := range allDevices {
		if d.Attempts >= lockout {
			lockedDevices++
		}

		if d.Active {
			activeSessions++
		}
	}

	registrations, err := ctrl.Registrations()
	if err != nil {
		log.Println("error getting registrations: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	pubkey, port, err := router.ServerDetails()
	if err != nil {
		log.Println("error getting server details: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	s, err := data.GetAllSettings()
	if err != nil {
		log.Println("error getting server settings: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	d := Dashboard{
		Page: Page{

			Description:  "Dashboard",
			Title:        "Dashboard",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},

		Port:            port,
		PublicKey:       pubkey.String(),
		ExternalAddress: s.ExternalAddress,
		Subnet:          config.Values.Wireguard.Range.String(),

		NumUsers:           len(allUsers),
		ActiveSessions:     activeSessions,
		RegistrationTokens: len(registrations),
		Devices:            len(allDevices),
		LockedDevices:      lockedDevices,
		UnenforcedMFA:      unenforcedMFA,
		LogItems:           LogQueue.ReadAll(),
	}

	err = renderDefaults(w, r, d, "management/dashboard.html")

	if err != nil {
		log.Println("unable to render dashboard page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}
