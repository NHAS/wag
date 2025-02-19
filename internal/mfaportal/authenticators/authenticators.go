package authenticators

import (
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"sync"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
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

type Authenticator interface {
	IsEnabled() bool

	Enable()
	Disable()

	ReloadSettings() error

	Type() string

	//FriendlyName is the name that is displayed in the MFA selection table
	FriendlyName() string

	Initialise(fw *router.Firewall, enabled bool) (routes *http.ServeMux, err error)
}

func StringsToMFA(methods []string) (ret []types.MFA) {
	for _, s := range methods {
		ret = append(ret, types.MFA(s))
	}
	return
}

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

func ReinitaliseMethods(method ...types.MFA) ([]types.MFA, error) {
	lck.Lock()
	defer lck.Unlock()

	var out []types.MFA

	var errRet error
	for _, m := range method {
		if a, ok := allMfa[m]; ok {
			err := a.ReloadSettings()
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

// GetAllAvaliableMethods returns All implemented authenticators in wag
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

	enabledMethods, err := data.GetEnabledAuthenicationMethods()
	if err != nil {
		return err
	}

	for method, handler := range allMfa {
		prefix := "/api/" + string(method)
		routes, err := handler.Initialise(firewall, slices.Contains(enabledMethods, string(method)))
		if err != nil {
			log.Println("failed to initialise method: ", method, "err: ", err)
			continue
		}

		mux.Handle(prefix, http.StripPrefix(prefix, checkEnabled(routes, allMfa[method])))
	}

	return nil
}

type enabled struct {
	next http.Handler
	auth Authenticator
}

func (d *enabled) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !d.auth.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	d.next.ServeHTTP(w, r)

}

func checkEnabled(next http.Handler, auth Authenticator) http.Handler {
	return &enabled{
		next: next,
		auth: auth,
	}
}

type mustBeUnregistered struct {
	next http.Handler
	fw   *router.Firewall
}

func (d *mustBeUnregistered) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	user := users.GetUserFromContext(r.Context())
	if user.IsEnforcingMFA() {
		http.NotFound(w, r)
		return
	}
	d.next.ServeHTTP(w, r)

}

func ensureUnregistered(next http.Handler, fw *router.Firewall) http.Handler {
	return &mustBeUnregistered{
		next: next,
		fw:   fw,
	}
}

type unauthed struct {
	next http.Handler
	fw   *router.Firewall
}

func (d *unauthed) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if d.fw.IsAuthed(utils.GetIPFromRequest(r).String()) {
		http.NotFound(w, r)
		return
	}
	d.next.ServeHTTP(w, r)

}

func isUnauthed(next http.Handler, fw *router.Firewall) http.Handler {
	return &unauthed{
		next: next,
		fw:   fw,
	}
}

func isUnauthedFunc(f http.HandlerFunc, fw *router.Firewall) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if fw.IsAuthed(utils.GetIPFromRequest(r).String()) {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		f(w, r)
	}
}

func isUnregisteredFunc(f http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		user := users.GetUserFromContext(r.Context())
		if user.IsEnforcingMFA() {
			http.NotFound(w, r)
			return
		}

		f(w, r)
	}
}
