package authenticators

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
)

var (
	allMfa = map[types.MFA]Authenticator{
		types.Totp:     new(Totp),
		types.Webauthn: new(Webauthn),
		types.Oidc:     new(Oidc),
		types.Pam:      new(Pam),
	}
	lck sync.RWMutex
)

func GetMethod(method string) (Authenticator, bool) {
	lck.RLock()
	defer lck.RUnlock()

	v, ok := allMfa[types.MFA(method)]
	if ok && v.IsEnabled() {
		return v, true
	}
	return nil, false
}

func DisableMethods(method ...types.MFA) {
	lck.Lock()
	defer lck.Unlock()

	for _, m := range method {
		if a, ok := allMfa[m]; ok {
			a.Disable()
		}
	}
}

func EnableMethods(method ...types.MFA) {
	lck.Lock()
	defer lck.Unlock()

	for _, m := range method {
		if a, ok := allMfa[m]; ok {
			a.Enable()
		}
	}
}

func ReinitaliseMethods(firewall *router.Firewall, method ...types.MFA) ([]types.MFA, error) {
	lck.Lock()
	defer lck.Unlock()

	var out []types.MFA

	var errRet error
	for _, m := range method {
		if a, ok := allMfa[m]; ok {
			err := a.Init(firewall)
			if err != nil {
				if errRet == nil {
					errRet = fmt.Errorf("%s failed to init: %s", m, err)
					continue
				}

				errRet = fmt.Errorf("%s failed to init: %s\n%s", m, err, errRet.Error())
			}
			out = append(out, m)
		}
	}

	return out, errRet
}

func NumberOfMethods() int {
	lck.RLock()
	defer lck.RUnlock()
	ret := 0
	for _, a := range allMfa {
		if a.IsEnabled() {
			ret++
		}
	}
	return ret
}

func GetAllEnabledMethods() (r []Authenticator) {
	lck.RLock()
	defer lck.RUnlock()

	var order []string
	for k := range allMfa {
		order = append(order, string(k))
	}

	sort.Strings(order)

	for _, m := range order {
		if auth, ok := allMfa[types.MFA(m)]; ok && auth.IsEnabled() {
			r = append(r, allMfa[types.MFA(m)])
		}
	}

	return
}

func GetAllAvaliableMethods() (r []Authenticator) {
	lck.RLock()
	defer lck.RUnlock()

	var order []string
	for k := range allMfa {
		order = append(order, string(k))
	}

	sort.Strings(order)

	for _, m := range order {
		r = append(r, allMfa[types.MFA(m)])
	}
	return
}

func AddMFARoutes(mux *http.ServeMux, firewall *router.Firewall) error {
	lck.Lock()
	defer lck.Unlock()

	for method, handler := range allMfa {
		mux.HandleFunc("GET /authorise/"+string(method)+"/", checkEnabled(handler, handler.AuthorisationAPI))
		mux.HandleFunc("POST /authorise/"+string(method)+"/", checkEnabled(handler, handler.AuthorisationAPI))
		mux.HandleFunc("GET /register_mfa/"+string(method)+"/", checkEnabled(handler, handler.RegistrationAPI))
		mux.HandleFunc("POST /register_mfa/"+string(method)+"/", checkEnabled(handler, handler.RegistrationAPI))

	}

	enabledMethods, err := data.GetEnabledAuthenicationMethods()
	if err != nil {
		return err
	}

	for _, method := range enabledMethods {
		err := allMfa[types.MFA(method)].Init(firewall)
		if err != nil {
			log.Println("failed to initialise method: ", method, "err: ", err)
			continue
		}
		allMfa[types.MFA(method)].Enable()
	}

	return nil
}

func checkEnabled(a Authenticator, f func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		if !a.IsEnabled() {
			http.NotFound(w, r)
			return
		}

		f(w, r)
	}
}

type Authenticator interface {
	Init(fw *router.Firewall) error

	IsEnabled() bool
	Enable()
	Disable()

	Type() string

	//FriendlyName is the name that is displayed in the MFA selection table
	FriendlyName() string

	//LogoutPath returns the redirection path that deauthenticates selected mfa method (mostly just "/" unless it's externally connected to something)
	LogoutPath() string

	//RegistrationAPI automatically added under /register_mfa/<mfa_method_name>
	RegistrationAPI(w http.ResponseWriter, r *http.Request)

	//AuthorisationAPI automatically added under /authorise/<mfa_method_name>
	AuthorisationAPI(w http.ResponseWriter, r *http.Request)

	//MFAPromptUI is executed in /authorise/ path to display UI when user browses to that path
	MFAPromptUI(w http.ResponseWriter, r *http.Request, username, ip string)

	//RegistrationUI is executed in /register_mfa/ path to show the UI for registration
	RegistrationUI(w http.ResponseWriter, r *http.Request, username, ip string)
}

func StringsToMFA(methods []string) (ret []types.MFA) {
	for _, s := range methods {
		ret = append(ret, types.MFA(s))
	}
	return
}
