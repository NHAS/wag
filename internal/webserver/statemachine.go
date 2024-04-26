package webserver

import (
	"log"
	"slices"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators"
	"github.com/NHAS/wag/internal/webserver/authenticators/types"
)

func registerListeners() error {
	_, err := data.RegisterEventListener(data.OidcDetailsKey, false, oidcChanges)
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.DomainKey, false, domainChanged)
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.MFAMethodsEnabledKey, false, enabledMethodsChanged)
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.IssuerKey, false, issuerKeyChanged)
	if err != nil {
		return err
	}
	return nil
}

// OidcDetailsKey = "wag-config-authentication-oidc"
func oidcChanges(key string, current data.OIDC, previous data.OIDC, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Oidc)
	case data.CREATED, data.MODIFIED:
		// Oidc and other mfa methods pull data from the etcd store themselves. So as dirty as this seems, its really just a notification to reinitialise themselves
		methods, err := data.GetAuthenicationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			return authenticators.ReinitaliseMethods(types.Oidc)
		}
	}

	return nil
}

// DomainKey            = "wag-config-authentication-domain"
func domainChanged(key string, current string, _ string, et data.EventType) error {
	switch et {
	case data.MODIFIED:

		methods, err := data.GetAuthenicationMethods()
		if err != nil {
			log.Println("Couldnt get authenication methods to enable oidc: ", err)
			return err
		}

		if slices.Contains(methods, string(types.Oidc)) {
			return authenticators.ReinitaliseMethods(types.Oidc)
		}
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func enabledMethodsChanged(key string, current []string, previous []string, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
	case data.CREATED:
		if err := authenticators.ReinitaliseMethods(authenticators.StringsToMFA(current)...); err != nil {
			return err
		}
		authenticators.EnableMethods(authenticators.StringsToMFA(current)...)

	case data.MODIFIED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)

		if err := authenticators.ReinitaliseMethods(authenticators.StringsToMFA(current)...); err != nil {
			return err
		}
		authenticators.EnableMethods(authenticators.StringsToMFA(current)...)
	}

	return nil
}

// IssuerKey    = "wag-config-authentication-issuer"
func issuerKeyChanged(key string, current string, previous string, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case data.CREATED, data.MODIFIED:
		return authenticators.ReinitaliseMethods(types.Totp, types.Webauthn)
	}

	return nil
}
