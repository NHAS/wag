package authenticators

import (
	"log"
	"net/http"
	"sort"
	"sync"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators/types"
)

var (
	mfa = map[types.MFA]Authenticator{}
	lck sync.RWMutex
)

func GetMethod(method string) (Authenticator, bool) {
	lck.RLock()
	defer lck.RUnlock()

	v, ok := mfa[types.MFA(method)]
	return v, ok
}

func RemoveMethod(method types.MFA) {
	lck.Lock()
	defer lck.Unlock()

	delete(mfa, method)
}

func NumberOfMethods() int {
	lck.RLock()
	defer lck.RUnlock()
	return len(mfa)
}

func GetAllEnabledMethods() (r []Authenticator) {
	lck.RLock()
	defer lck.RUnlock()

	order := []string{}
	for k := range mfa {
		order = append(order, string(k))
	}

	sort.Strings(order)

	for _, m := range order {
		r = append(r, mfa[types.MFA(m)])
	}

	return
}

func SetRoutesFromMethods(mux *http.ServeMux) {

	enabledMethods, err := data.GetAuthenicationMethods()
	if err != nil {
		log.Println("error fetching cluster data for authentication methods: ", err)
		return
	}

	lck.Lock()
	newMap := make(map[types.MFA]Authenticator)
	for _, method := range enabledMethods {
		switch types.MFA(method) {
		case types.Totp:
			newMap[types.MFA(method)] = new(Totp)

		case types.Webauthn:
			newMap[types.MFA(method)] = new(Webauthn)

		case types.Oidc:
			newMap[types.MFA(method)] = new(Oidc)

		case types.Pam:
			newMap[types.MFA(method)] = new(Pam)
		default:
			log.Println("not adding unknown mfa method: ", method)
			continue
		}

		err = newMap[types.MFA(method)].Init()
		if err != nil {
			log.Println("could not initalise auth method: ", method, "this method will not be enabled, err: ", err)
			continue
		}
	}
	mfa = newMap
	lck.Unlock()

	lck.RLock()
	for method, handler := range mfa {
		mux.HandleFunc("/authorise/"+string(method)+"/", handler.AuthorisationAPI)
		mux.HandleFunc("/register_mfa/"+string(method)+"/", handler.RegistrationAPI)

	}
	lck.RUnlock()
}

type Authenticator interface {
	Init() error

	Type() string

	// Name that is displayed in the MFA selection table
	FriendlyName() string

	// Redirection path that deauthenticates selected mfa method (mostly just "/" unless its externally connected to something)
	LogoutPath() string

	// Automatically added under /register_mfa/<mfa_method_name>
	RegistrationAPI(w http.ResponseWriter, r *http.Request)

	// Automatically added under /authorise/<mfa_method_name>
	AuthorisationAPI(w http.ResponseWriter, r *http.Request)

	// Executed in /authorise/ path to display UI when user browses to that path
	MFAPromptUI(w http.ResponseWriter, r *http.Request, username, ip string)

	// Executed in /register_mfa/ path to show the UI for registration
	RegistrationUI(w http.ResponseWriter, r *http.Request, username, ip string)
}
