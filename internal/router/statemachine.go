package router

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd/watch"
	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (f *Firewall) handleEvents() error {

	ctx, cancel := context.WithCancel(context.Background())
	f.watchersCancel = cancel

	err := data.Config.Webserver.Tunnel.SessionInactivityTimeoutMinutes().Watch(ctx, f.db.Raw()).Start(
		watch.Created(f.inactivityTimeoutChanges),
		watch.Modified(f.inactivityTimeoutChanges),
	)
	if err != nil {
		return err
	}

	err = data.InternalConfig.Devices.Machines().Watch(ctx, f.db.Raw()).Start(
		watch.Created(f.addDevice),
		watch.Modified(f.deviceChanges),
		watch.Deleted(f.delDevice),
	)
	if err != nil {
		return err
	}

	err = data.InternalConfig.Users().Watch(ctx, f.db.Raw()).Start(
		watch.Created(f.addUser),
		watch.Modified(f.userChanges),
		watch.Deleted(f.delUser),
	)
	if err != nil {
		return err
	}

	err = data.Config.Acls.Policies().
		Watch(ctx, f.db.Raw()).
		Start(watch.All(f.aclsChanges))
	if err != nil {
		return err
	}

	err = data.InternalConfig.Indexes.UserMembership().
		Watch(ctx, f.db.Raw()).
		Start(watch.All(f.groupChanges))
	if err != nil {
		return err
	}

	return nil

}

func (f *Firewall) inactivityTimeoutChanges(ctx context.Context, event watch.Event[int]) error {

	if event.Current == event.Previous {
		return nil
	}

	if err := f.SetInactivityTimeout(event.Current); err != nil {
		return fmt.Errorf("unable to set inactivity timeout: %s", err)
	}

	log.Info().Msg("inactivity timeout changed")

	return nil
}

func (f *Firewall) addDevice(ctx context.Context, event watch.Event[config.Device]) error {

	key, _ := wgtypes.ParseKey(event.Current.Publickey)
	err := f.AddPeer(key, event.Current.Username, event.Current.Address, event.Current.PresharedKey, event.Current.AssociatedNode)
	if err != nil {
		return fmt.Errorf("unable to create peer: %s: err: %s", event.Current.Address, err)
	}

	log.Info().Str("address", event.Current.Address).Msg("added peer")

	return nil
}

func (f *Firewall) deviceChanges(ctx context.Context, event watch.Event[config.Device]) error {

	lockout, err := f.db.GetLockout()
	if err != nil {
		return fmt.Errorf("cannot get lockout: %s", err)
	}

	if event.Current.Publickey != event.Previous.Publickey {
		key, _ := wgtypes.ParseKey(event.Current.Publickey)
		err := f.ReplacePeer(event.Previous, key)
		if err != nil {
			return fmt.Errorf("failed to replace peer pub key: %s", err)
		}

		log.Info().Str("address", event.Current.Address).Msg("replaced peer public key")

	}

	if f.IsAuthed(event.Current.Address) {
		if event.Current.Endpoint.String() != event.Previous.Endpoint.String() {

			log.Info().Str("username", event.Current.Username).
				Str("address", event.Current.Address).
				Str("new_endpoint", event.Current.Endpoint.String()).
				Str("previous_endpoint", event.Previous.Endpoint.String()).
				Msg("device has changed endpoint, setting challenge")

			err := f.Deauthenticate(event.Current.Address)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate device %s: %s", event.Current.Address, err)
			}

			// Will set a record deleted after 30 seconds that a device can use to reauthenticate
			err = f.db.SetChallenge(event.Current)
			if err != nil {
				return fmt.Errorf("failed to set device challenge: %w", err)
			}
		}

		if event.Current.Attempts > lockout || // If the number of authentication attempts on a device has exceeded the max
			event.Current.Authorised.IsZero() { // If we've explicitly deauthorised a device

			var reasons []string
			if event.Current.Attempts > lockout {
				reasons = []string{fmt.Sprintf("exceeded lockout (%d)", event.Current.Attempts)}
			}

			if event.Current.Authorised.IsZero() {
				reasons = append(reasons, "session terminated")
			}

			err := f.Deauthenticate(event.Current.Address)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate device %s: %s", event.Current.Address, err)
			}

			log.Info().Str("address", event.Current.Address).
				Str("username", event.Current.Username).
				Str("reason", strings.Join(reasons, ",")).Msg("deauthed device")

		}
	}

	if event.Current.AssociatedNode != event.Previous.AssociatedNode {
		err := f.UpdateNodeAssociation(event.Current)
		if err != nil {
			return fmt.Errorf("cannot change device node association %s:%s: %s", event.Current.Address, event.Current.Username, err)
		}

		log.Info().Str("address", event.Current.Address).
			Str("username", event.Current.Username).
			Str("previous_node", event.Previous.AssociatedNode.String()).
			Str("current_node", event.Current.AssociatedNode.String()).
			Msg("changed device node association")

	}

	// If the authorisation state has changed and is not disabled
	if f.db.HasDeviceAuthorised(event.Current, event.Previous) {
		err := f.SetAuthorized(event.Current.Address, event.Current.AssociatedNode)

		if err != nil {
			return fmt.Errorf("cannot authorize device %s: %s", event.Current.Address, err)
		}

		log.Info().Str("address", event.Current.Address).
			Str("username", event.Current.Username).
			Msg("authorized device")

	}

	return nil
}

func (f *Firewall) delDevice(ctx context.Context, event watch.Event[config.Device]) error {

	err := f.RemovePeer(event.Previous.Publickey, event.Previous.Address)
	if err != nil {
		return fmt.Errorf("unable to remove peer: %s: err: %s", event.Previous.Address, err)
	}

	log.Info().Str("address", event.Previous.Address).
		Str("username", event.Previous.Username).
		Msg("removed peer")
	return nil
}

func (f *Firewall) addUser(ctx context.Context, event watch.Event[config.UserModel]) error {
	err := f.AddUser(event.Current.Username)
	if err != nil {
		return fmt.Errorf("cannot create user %s: %s", event.Current.Username, err)
	}

	log.Info().Str("username", event.Current.Username).
		Msg("added user")
	return nil
}

// shouldDeauthenticateUser determines if a user should be deauthenticated
// based on changes to their security settings
func (f *Firewall) shouldDeauthenticateUser(current, previous config.UserModel) bool {
	// MFA settings changed
	if current.Mfa != previous.Mfa {
		return true
	}

	// MFA type changed
	if current.MfaType != previous.MfaType {
		return true
	}

	// if users mfa was reset
	if !current.Enforcing {
		return true
	}

	// MFA type is unset/invalid
	if types.MFA(current.MfaType) == types.Unset {
		return true
	}

	return false
}

func (f *Firewall) userChanges(ctx context.Context, event watch.Event[config.UserModel]) error {

	if event.Current.Locked != event.Previous.Locked || event.Current.Locked {

		log.Info().
			Str("username", event.Current.Username).
			Bool("locked", event.Current.Locked).
			Msg("locked user")

		err := f.SetLockAccount(event.Current.Username, event.Current.Locked)
		if err != nil {
			return fmt.Errorf("cannot lock user %s: %s", event.Current.Username, err)
		}
	}

	if f.shouldDeauthenticateUser(event.Current, event.Previous) {

		log.Info().
			Str("username", event.Current.Username).
			Msg("deauthenticated user")

		err := f.DeauthenticateAllDevices(event.Current.Username)
		if err != nil {
			return fmt.Errorf("cannot deauthenticate user %s: %s", event.Current.Username, err)
		}
	}

	return nil
}

func (f *Firewall) delUser(ctx context.Context, event watch.Event[config.UserModel]) error {
	err := f.RemoveUser(event.Previous.Username)
	if err != nil {
		return fmt.Errorf("cannot remove user %s: %s", event.Previous.Username, err)
	}

	log.Info().
		Str("username", event.Previous.Username).
		Msg("removed user")

	return nil
}

func (f *Firewall) aclsChanges(ctx context.Context, event watch.Event[*acls.Acl]) error {

	// TODO refresh the users that the acl applies to as a potential performance improvement
	switch event.Type {
	case watch.CREATED, watch.DELETED, watch.MODIFIED:
		err := f.RefreshConfiguration()
		if err != nil {
			return fmt.Errorf("failed to refresh configuration: %s", err)
		}
		log.Info().Msg("refreshed configuration")

	}

	return nil
}

func (f *Firewall) groupChanges(ctx context.Context, event watch.Event[config.MembershipInfo]) error {

	username := filepath.Base(event.Key)

	switch event.Type {
	case watch.CREATED, watch.DELETED, watch.MODIFIED:

		err := f.RefreshUserAcls(username)
		if err != nil {
			return fmt.Errorf("failed to refresh acls for user %s: %s", username, err)
		}

		log.Info().Str("username", username).Msg("refreshed acls")
	}
	return nil
}
