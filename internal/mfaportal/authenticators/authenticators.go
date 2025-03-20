package authenticators

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
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

	Initialise() error

	Type() string

	//FriendlyName is the name that is displayed in the MFA selection table
	FriendlyName() string

	GetRoutes(fw *router.Firewall) (routes *http.ServeMux, err error)
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

	log.Println("disabling: ", method)

	for _, m := range method {
		if a, ok := allMfa[m]; ok {
			a.Disable()
		}
	}
}

func ReinitialiseMethod(method types.MFA) error {
	lck.Lock()
	defer lck.Unlock()

	if a, ok := allMfa[method]; ok {
		if !a.IsEnabled() {
			return nil
		}

		err := a.Initialise()
		if err != nil {
			a.Disable()
			return err
		}

		return nil
	}

	return fmt.Errorf("method not found: %q", method)
}

func enableMethod(method types.MFA) error {
	if a, ok := allMfa[method]; ok {
		// If the method is already enabled, dont re-enable it
		if a.IsEnabled() {
			return nil
		}

		err := a.Initialise()
		if err != nil {
			a.Disable()
			return err
		}
		a.Enable()
		return nil
	}

	return fmt.Errorf("mfa method %q not found", method)
}

func SetEnabledMethods(method ...types.MFA) error {
	lck.Lock()
	defer lck.Unlock()

	enabledMfa := map[types.MFA]bool{}
	for _, m := range method {
		enabledMfa[m] = true
	}

	var errRet []error
	for m, handler := range allMfa {
		handler.Disable()
		if enabledMfa[m] {
			if err := enableMethod(m); err != nil {
				errRet = append(errRet, err)
			}
		}
	}

	return errors.Join(errRet...)
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

	enabledMethods, err := data.GetEnabledAuthenticationMethods()
	if err != nil {
		return err
	}

	depreciatedMessage := func(w http.ResponseWriter, r *http.Request) {
		log.Println("SSO ERROR. YOU ARE USING A DEPRECATED PATH /authorise/oidc/, please update to /api/oidc/authorise/callback/")
		http.Error(w, "Deprecated sso path", http.StatusBadRequest)
	}

	mux.HandleFunc("/authorise/oidc/", depreciatedMessage)
	mux.HandleFunc("/authorise/oidc", depreciatedMessage)

	for method, handler := range allMfa {
		handler.Disable()

		prefix := "/api/" + string(method)

		isEnabled := slices.Contains(enabledMethods, string(method))

		routes, err := handler.GetRoutes(firewall)
		if err != nil {

			log.Println("failed to get routes for mfa method: ", method, "err: ", err)
			continue
		}

		err = handler.Initialise()
		if err != nil {
			handler.Disable()
			log.Println("failed to initialise mfa method: ", method, "err: ", err)
			continue
		}

		if isEnabled {
			handler.Enable()
		}
		// Directly register each handler from routes to the main mux with the proper prefix
		mux.Handle(prefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First check if the method is enabled
			if !handler.IsEnabled() {
				http.NotFound(w, r)
				return
			}

			// Strip the prefix and pass to routes
			r2 := *r
			r2.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			routes.ServeHTTP(w, &r2)
		}))
	}

	return nil
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

// Make sure the user hasnt already registered an MFA method
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

// Ensure that the calling vpn user is unauthenticated
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
