package router

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/data/watcher"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (f *Firewall) handleEvents() error {

	t, err := watcher.Watch(f.db, data.InactivityTimeoutKey, true, watcher.OnCreate(f.inactivityTimeoutChanges), watcher.OnModification(f.inactivityTimeoutChanges))
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, t)

	d, err := watcher.Watch(f.db, config.DevicesPrefix, true, watcher.OnCreate(f.addDevice), watcher.OnModification(f.deviceChanges), watcher.OnDelete(f.delDevice))
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, d)

	u, err := watcher.Watch(f.db, data.UsersPrefix, true, watcher.OnCreate(f.addUser), watcher.OnModification(f.userChanges), watcher.OnDelete(f.delUser))
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, u)

	a, err := watcher.WatchAll(f.db, data.AclsPrefix, true, f.aclsChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, a)

	g, err := watcher.WatchAll(f.db, data.GroupMembershipPrefix, true, f.groupChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, g)

	return nil

}

func (f *Firewall) inactivityTimeoutChanges(_ string, current, previous int) error {

	if current == previous {
		return nil
	}

	if err := f.SetInactivityTimeout(current); err != nil {
		return fmt.Errorf("unable to set inactivity timeout: %s", err)
	}

	log.Info().Msg("inactivity timeout changed")

	return nil
}

func (f *Firewall) addDevice(_ string, current, previous config.Device) error {
	key, _ := wgtypes.ParseKey(current.Publickey)
	err := f.AddPeer(key, current.Username, current.Address, current.PresharedKey, current.AssociatedNode)
	if err != nil {
		return fmt.Errorf("unable to create peer: %s: err: %s", current.Address, err)
	}

	log.Info().Str("address", current.Address).Msg("added peer")

	return nil
}

func (f *Firewall) deviceChanges(_ string, current, previous config.Device) error {

	lockout, err := f.db.GetLockout()
	if err != nil {
		return fmt.Errorf("cannot get lockout: %s", err)
	}

	if current.Publickey != previous.Publickey {
		key, _ := wgtypes.ParseKey(current.Publickey)
		err := f.ReplacePeer(previous, key)
		if err != nil {
			return fmt.Errorf("failed to replace peer pub key: %s", err)
		}

		log.Info().Str("address", current.Address).Msg("replaced peer public key")

	}

	if f.IsAuthed(current.Address) {
		if current.Endpoint.String() != previous.Endpoint.String() {

			log.Info().Str("username", current.Username).
				Str("address", current.Address).
				Str("new_endpoint", current.Endpoint.String()).
				Str("previous_endpoint", previous.Endpoint.String()).
				Msg("device has changed endpoint, setting challenge")

			err := f.Deauthenticate(current.Address)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate device %s: %s", current.Address, err)
			}

			// Will set a record deleted after 30 seconds that a device can use to reauthenticate
			err = current.SetChallenge(f.db.Raw())
			if err != nil {
				return fmt.Errorf("failed to set device challenge: %w", err)
			}
		}

		if current.Attempts > lockout || // If the number of authentication attempts on a device has exceeded the max
			current.Authorised.IsZero() { // If we've explicitly deauthorised a device

			var reasons []string
			if current.Attempts > lockout {
				reasons = []string{fmt.Sprintf("exceeded lockout (%d)", current.Attempts)}
			}

			if current.Authorised.IsZero() {
				reasons = append(reasons, "session terminated")
			}

			err := f.Deauthenticate(current.Address)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate device %s: %s", current.Address, err)
			}

			log.Info().Str("address", current.Address).
				Str("username", current.Username).
				Str("reason", strings.Join(reasons, ",")).Msg("deauthed device")

		}
	}

	if current.AssociatedNode != previous.AssociatedNode {
		err := f.UpdateNodeAssociation(current)
		if err != nil {
			return fmt.Errorf("cannot change device node association %s:%s: %s", current.Address, current.Username, err)
		}

		log.Info().Str("address", current.Address).
			Str("username", current.Username).
			Str("previous_node", previous.AssociatedNode.String()).
			Str("current_node", current.AssociatedNode.String()).
			Msg("changed device node association")

	}

	// If the authorisation state has changed and is not disabled
	if f.db.HasDeviceAuthorised(current, previous) {
		err := f.SetAuthorized(current.Address, current.AssociatedNode)

		if err != nil {
			return fmt.Errorf("cannot authorize device %s: %s", current.Address, err)
		}

		log.Info().Str("address", current.Address).
			Str("username", current.Username).
			Msg("authorized device")

	}

	return nil
}

func (f *Firewall) delDevice(_ string, current, previous config.Device) error {
	err := f.RemovePeer(current.Publickey, current.Address)
	if err != nil {
		return fmt.Errorf("unable to remove peer: %s: err: %s", current.Address, err)
	}

	log.Info().Str("address", current.Address).
		Str("username", current.Username).
		Msg("removed peer")
	return nil
}

func (f *Firewall) addUser(_ string, current, previous config.UserModel) error {
	err := f.AddUser(current.Username)
	if err != nil {
		return fmt.Errorf("cannot create user %s: %s", current.Username, err)
	}

	log.Info().Str("username", current.Username).
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

func (f *Firewall) userChanges(_ string, current, previous config.UserModel) error {

	if current.Locked != previous.Locked || current.Locked {

		log.Info().
			Str("username", current.Username).
			Bool("locked", current.Locked).
			Msg("locked user")

		err := f.SetLockAccount(current.Username, current.Locked)
		if err != nil {
			return fmt.Errorf("cannot lock user %s: %s", current.Username, err)
		}
	}

	if f.shouldDeauthenticateUser(current, previous) {

		log.Info().
			Str("username", current.Username).
			Msg("deauthenticated user")

		err := f.DeauthenticateAllDevices(current.Username)
		if err != nil {
			return fmt.Errorf("cannot deauthenticate user %s: %s", current.Username, err)
		}
	}

	return nil
}

func (f *Firewall) delUser(_ string, current, previous config.UserModel) error {
	err := f.RemoveUser(current.Username)
	if err != nil {
		return fmt.Errorf("cannot remove user %s: %s", current.Username, err)
	}

	log.Info().
		Str("username", current.Username).
		Msg("removed user")

	return nil
}

func (f *Firewall) aclsChanges(_ string, et data.EventType, _, _ acls.Acl) error {
	// TODO refresh the users that the acl applies to as a potential performance improvement
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:
		err := f.RefreshConfiguration()
		if err != nil {
			return fmt.Errorf("failed to refresh configuration: %s", err)
		}
		log.Info().Msg("refreshed configuration")

	}

	return nil
}

func (f *Firewall) groupChanges(key string, et data.EventType, _, _ any) error {

	keyParts, err := f.db.SplitKey(2, data.GroupMembershipPrefix, key)
	if err != nil {
		return fmt.Errorf("key was incorrect, this is a bug: %w", err)
	}

	username := keyParts[0]

	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:

		err := f.RefreshUserAcls(username)
		if err != nil {
			return fmt.Errorf("failed to refresh acls for user %s: %s", username, err)
		}

		log.Info().Str("username", username).Msg("refreshed acls")
	}
	return nil
}
