package mfaportal

import (
	"log"
	"slices"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/data/watcher"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
)

func (mp *MfaPortal) registerListeners() error {

	o, err := watcher.Watch(mp.db, data.OidcDetailsKey, false, watcher.OnDelete(mp.oidcDeleted), watcher.OnCreate(mp.oidcChanged), watcher.OnModification(mp.oidcChanged))
	if err != nil {
		return err
	}
	mp.watchers = append(mp.watchers, o)

	d, err := watcher.Watch(mp.db, data.TunnelWebServerConfigKey, false, watcher.OnModification(mp.domainChanged))
	if err != nil {
		return err
	}
	mp.watchers = append(mp.watchers, d)

	m, err := watcher.WatchAll(mp.db, data.MFAMethodsEnabledKey, false, mp.enabledMethodsChanged)
	if err != nil {
		return err
	}
	mp.watchers = append(mp.watchers, m)

	i, err := watcher.WatchAll(mp.db, data.IssuerKey, false, mp.issuerKeyChanged)
	if err != nil {
		return err
	}
	mp.watchers = append(mp.watchers, i)

	return nil
}

func (mp *MfaPortal) oidcDeleted(_ string, current data.OIDC, previous data.OIDC) error {
	authenticators.DisableMethods(types.Oidc)
	return nil
}

// OidcDetailsKey = "wag-config-authentication-oidc"
func (mp *MfaPortal) oidcChanged(_ string, current data.OIDC, previous data.OIDC) error {

	if current.Equals(&previous) {
		return nil
	}

	// Oidc and other mfa methods pull data from the etcd store themselves. So as dirty as this seems, its really just a notification to reinitialise themselves
	methods, err := mp.db.GetEnabledMFAMethods()
	if err != nil {
		log.Println("Couldnt get authenication methods to enable oidc: ", err)
		return err
	}

	if slices.Contains(methods, string(types.Oidc)) {
		return authenticators.ReinitialiseMethod(mp.db, types.Oidc)
	}

	return nil
}

func (mp *MfaPortal) domainChanged(_ string, current, previous data.WebserverConfiguration) error {

	if current.Equals(&previous) {
		return nil
	}

	methods, err := mp.db.GetEnabledMFAMethods()
	if err != nil {
		log.Println("Couldnt get authenication methods to enable oidc: ", err)
		return err
	}

	if slices.Contains(methods, string(types.Oidc)) {
		return authenticators.ReinitialiseMethod(mp.db, types.Oidc)
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func (mp *MfaPortal) enabledMethodsChanged(_ string, et data.EventType, current, previous []string) (err error) {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
	case data.CREATED, data.MODIFIED:
		if !slices.Equal(current, previous) {
			err = authenticators.SetEnabledMethods(mp.db, authenticators.StringsToMFA(current)...)
		}
	}

	return err
}

// IssuerKey    = "wag-config-authentication-issuer"
func (mp *MfaPortal) issuerKeyChanged(_ string, et data.EventType, current, previous string) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case data.CREATED, data.MODIFIED:
		if current == previous {
			return nil
		}

		methods, err := mp.db.GetEnabledMFAMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Totp)) {
			err = authenticators.ReinitialiseMethod(mp.db, types.Totp)
		}

		if slices.Contains(methods, string(types.Webauthn)) {
			err = authenticators.ReinitialiseMethod(mp.db, types.Webauthn)
		}

		return err
	}

	return nil
}
