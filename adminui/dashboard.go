package adminui

import (
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/config"
)

func (au *AdminUI) populateDashboard(w http.ResponseWriter, r *http.Request) {

	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	allUsers, err := au.ctrl.ListUsers("")
	if err != nil {
		log.Println("error getting users: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	unenforcedMFA := 0
	for _, u := range allUsers {
		if !u.Enforcing {
			unenforcedMFA++
		}

	}

	allDevices, err := au.ctrl.ListDevice("")
	if err != nil {
		log.Println("error getting devices: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	lockout, err := au.ctrl.GetLockout()
	if err != nil {
		log.Println("error getting lockout: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
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

	registrations, err := au.ctrl.Registrations()
	if err != nil {
		log.Println("error getting registrations: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	pubkey, port, err := au.firewall.ServerDetails()
	if err != nil {
		log.Println("error getting server details: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	s, err := au.ctrl.GetAllSettings()
	if err != nil {
		log.Println("error getting server settings: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}

	d := Dashboard{
		Page: Page{

			Description: "Dashboard",
			Title:       "Dashboard",
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
		LogItems:           au.logQueue.ReadAll(),
	}

	err = au.renderDefaults(w, r, d, "management/dashboard.html")

	if err != nil {
		log.Println("unable to render dashboard page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}
}
