package mfaportal

import (
	"context"
	"slices"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd/watch"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
)

func (mp *MfaPortal) registerListeners() error {

	ctx, cancel := context.WithCancel(context.Background())
	mp.watchersCancel = cancel

	o, err := watch.Watch(mp.db, data.OidcDetailsKey, false, watch.OnDelete(mp.oidcDeleted), watch.OnCreate(mp.oidcChanged), watch.OnModification(mp.oidcChanged))
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Tunnel.HTTPSettings.Domain().Watch(ctx, mp.db.Raw()).Start(
		watch.Modified(mp.domainChanged),
	)
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Tunnel.Methods().Watch(ctx, mp.db.Raw()).Start(
		watch.All(mp.enabledMethodsChanged),
	)
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Tunnel.Issuer().Watch(ctx, mp.db.Raw()).Start(
		watch.All(mp.issuerKeyChanged),
	)
	if err != nil {
		return err
	}

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
		log.Error().Err(err).Msg("Couldnt get authenication methods to reinitialise oidc")
		return err
	}

	if slices.Contains(methods, string(types.Oidc)) {
		return authenticators.ReinitialiseMethod(mp.db, types.Oidc)
	}

	return nil
}

func (mp *MfaPortal) domainChanged(ctx context.Context, event watch.Event[string]) error {

	if event.Current == event.Previous {
		return nil
	}

	methods, err := mp.db.GetEnabledMFAMethods()
	if err != nil {
		log.Error().Err(err).Msg("Couldnt get authenication methods to reinitialise oidc")
		return err
	}

	if slices.Contains(methods, string(types.Oidc)) {
		return authenticators.ReinitialiseMethod(mp.db, types.Oidc)
	}

	return nil
}

// MethodsEnabledKey    = "wag-config-authentication-methods"
func (mp *MfaPortal) enabledMethodsChanged(ctx context.Context, event watch.Event[[]string]) (err error) {

	switch event.Type {
	case watch.DELETED:
		authenticators.DisableMethods(authenticators.StringsToMFA(event.Previous)...)
	case watch.CREATED, watch.MODIFIED:
		if event.Current == nil {
			return nil
		}

		if !slices.Equal(event.Current, event.Previous) {
			err = authenticators.SetEnabledMethods(mp.db, authenticators.StringsToMFA(event.Current)...)
		}
	}

	return err
}

// IssuerKey    = "wag-config-authentication-issuer"
func (mp *MfaPortal) issuerKeyChanged(ctx context.Context, event watch.Event[string]) error {
	switch event.Type {
	case watch.DELETED:
		authenticators.DisableMethods(types.Totp, types.Webauthn)
	case watch.CREATED, watch.MODIFIED:
		if event.Current == event.Previous {
			return nil
		}

		methods, err := mp.db.GetEnabledMFAMethods()
		if err != nil {
			log.Error().Err(err).Msg("Couldnt get authenication methods to reinitialise totp and webauth")
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
