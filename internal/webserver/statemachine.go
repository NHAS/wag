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
			_, err := authenticators.ReinitaliseMethods(types.Oidc)

			return err
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
			_, err := authenticators.ReinitaliseMethods(types.Oidc)

			return err
		}
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func enabledMethodsChanged(key string, current []string, previous []string, et data.EventType) (err error) {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
	case data.CREATED:
		var initdMethods []types.MFA

		initdMethods, err = authenticators.ReinitaliseMethods(authenticators.StringsToMFA(current)...)
		authenticators.EnableMethods(initdMethods...)

	case data.MODIFIED:
		var initdMethods []types.MFA

		authenticators.DisableMethods(authenticators.StringsToMFA(previous)...)
		initdMethods, err = authenticators.ReinitaliseMethods(authenticators.StringsToMFA(current)...)

		authenticators.EnableMethods(initdMethods...)
	}

	return err
}

// IssuerKey    = "wag-config-authentication-issuer"
func issuerKeyChanged(key string, current string, previous string, et data.EventType) error {
	switch et {
	case data.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case data.CREATED, data.MODIFIED:
		_, err := authenticators.ReinitaliseMethods(types.Totp, types.Webauthn)
		return err
	}

	return nil
}
