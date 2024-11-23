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

	mp.listenerKeys.Domain, err = data.RegisterEventListener(data.DomainKey, false, mp.domainChanged)
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
		methods, err := data.GetEnabledAuthenicationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			_, err := authenticators.ReinitaliseMethods(mp.firewall, types.Oidc)

			return err
		}
	}

	return nil
}

// DomainKey            = "wag-config-authentication-domain"
func (mp *MfaPortal) domainChanged(_ string, _ string, _ string, et data.EventType) error {
	switch et {
	case data.MODIFIED:

		methods, err := data.GetEnabledAuthenicationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			_, err := authenticators.ReinitaliseMethods(mp.firewall, types.Oidc)

			return err
		}
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func (mp *MfaPortal) enabledMethodsChanged(_ string, current, previous []string, et data.EventType) (err error) {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
	case data.CREATED:
		var initdMethods []types.MFA

		initdMethods, err = authenticators.ReinitaliseMethods(mp.firewall, authenticators.StringsToMFA(current)...)
		authenticators.EnableMethods(initdMethods...)

	case data.MODIFIED:
		var initdMethods []types.MFA

		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
		initdMethods, err = authenticators.ReinitaliseMethods(mp.firewall, authenticators.StringsToMFA(current)...)

		authenticators.EnableMethods(initdMethods...)
	}

	return err
}

// IssuerKey    = "wag-config-authentication-issuer"
func (mp *MfaPortal) issuerKeyChanged(_ string, _, _ string, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case data.CREATED, data.MODIFIED:
		_, err := authenticators.ReinitaliseMethods(mp.firewall, types.Totp, types.Webauthn)
		return err
	}

	return nil
}
