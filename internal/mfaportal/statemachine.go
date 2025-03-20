package mfaportal

import (
	"log"
	"slices"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
)

func (mp *MfaPortal) registerListeners() error {
	var err error

	mp.listenerKeys.Oidc, err = data.RegisterEventListener(data.OidcDetailsKey, false, mp.oidcChanges)
	if err != nil {
		return err
	}

	mp.listenerKeys.Domain, err = data.RegisterEventListener(data.TunnelWebServerConfigKey, false, mp.domainChanged)
	if err != nil {
		return err
	}

	mp.listenerKeys.MFAMethods, err = data.RegisterEventListener(data.MFAMethodsEnabledKey, false, mp.enabledMethodsChanged)
	if err != nil {
		return err
	}

	mp.listenerKeys.Issuer, err = data.RegisterEventListener(data.IssuerKey, false, mp.issuerKeyChanged)
	if err != nil {
		return err
	}
	return nil
}

func (mp *MfaPortal) deregisterListeners() {
	eventKeys := []string{
		mp.listenerKeys.Oidc,
		mp.listenerKeys.Domain,
		mp.listenerKeys.MFAMethods,
		mp.listenerKeys.Issuer,
	}

	for _, key := range eventKeys {
		err := data.DeregisterEventListener(key)
		if err != nil {
			log.Println("failed to deregister: ", err)
		}
	}
}

// OidcDetailsKey = "wag-config-authentication-oidc"
func (mp *MfaPortal) oidcChanges(_ string, _ data.OIDC, _ data.OIDC, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Oidc)
	case data.CREATED, data.MODIFIED:
		// Oidc and other mfa methods pull data from the etcd store themselves. So as dirty as this seems, its really just a notification to reinitialise themselves
		methods, err := data.GetEnabledAuthenticationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			return authenticators.ReinitialiseMethod(types.Oidc)
		}
	}

	return nil
}

func (mp *MfaPortal) domainChanged(_ string, _, _ data.WebserverConfiguration, et data.EventType) error {
	switch et {
	case data.MODIFIED:

		methods, err := data.GetEnabledAuthenticationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			return authenticators.ReinitialiseMethod(types.Oidc)
		}
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func (mp *MfaPortal) enabledMethodsChanged(_ string, current, previous []string, et data.EventType) (err error) {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
	case data.CREATED, data.MODIFIED:
		err = authenticators.SetEnabledMethods(authenticators.StringsToMFA(current)...)
	}

	return err
}

// IssuerKey    = "wag-config-authentication-issuer"
func (mp *MfaPortal) issuerKeyChanged(_ string, _, _ string, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case data.CREATED, data.MODIFIED:
		methods, err := data.GetEnabledAuthenticationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Totp)) {
			err = authenticators.ReinitialiseMethod(types.Totp)
		}

		if slices.Contains(methods, string(types.Webauthn)) {
			err = authenticators.ReinitialiseMethod(types.Webauthn)
		}

		return err
	}

	return nil
}
