package router

import (
	"fmt"
	"log"
	"strings"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (f *Firewall) handleEvents() error {

	d, err := data.Watch(data.DevicesPrefix, true, f.deviceChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, d)

	u, err := data.Watch(data.UsersPrefix, true, f.userChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, u)

	a, err := data.Watch(data.AclsPrefix, true, f.aclsChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, a)

	g, err := data.Watch(data.GroupMembershipPrefix, true, f.groupChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, g)

	t, err := data.Watch(data.InactivityTimeoutKey, true, f.inactivityTimeoutChanges)
	if err != nil {
		return err
	}
	f.watchers = append(f.watchers, t)

	return nil

}

func (f *Firewall) inactivityTimeoutChanges(_ string, et data.EventType, current, previous int) error {

	switch et {
	case data.MODIFIED, data.CREATED:
		if current != previous {
			if err := f.SetInactivityTimeout(current); err != nil {
				return fmt.Errorf("unable to set inactivity timeout: %s", err)
			}
			log.Println("inactivity timeout changed")
		}
	}

	return nil
}

func (f *Firewall) deviceChanges(_ string, et data.EventType, current, previous data.Device) error {
	switch et {
	case data.DELETED:

		err := f.RemovePeer(current.Publickey, current.Address)
		if err != nil {
			return fmt.Errorf("unable to remove peer: %s: err: %s", current.Address, err)
		}
		log.Println("removed peer: ", current.Address)

	case data.CREATED:

		key, _ := wgtypes.ParseKey(current.Publickey)
		err := f.AddPeer(key, current.Username, current.Address, current.PresharedKey, current.AssociatedNode)
		if err != nil {
			return fmt.Errorf("unable to create peer: %s: err: %s", current.Address, err)
		}

		log.Println("added peer: ", current.Address)

	case data.MODIFIED:

		if current.Publickey != previous.Publickey {
			key, _ := wgtypes.ParseKey(current.Publickey)
			err := f.ReplacePeer(previous, key)
			if err != nil {
				return fmt.Errorf("failed to replace peer pub key: %s", err)
			}
			log.Println("replaced peer public key: ", current.Address)
		}

		lockout, err := data.GetLockout()
		if err != nil {
			return fmt.Errorf("cannot get lockout: %s", err)
		}

		if f.IsAuthed(current.Address) {
			if current.Endpoint.String() != previous.Endpoint.String() {

				log.Printf("challenging %s:%s device, as endpoint changed: %s -> %s", current.Username, current.Address, current.Endpoint.String(), previous.Endpoint.String())

				err := f.Deauthenticate(current.Address)
				if err != nil {
					return fmt.Errorf("cannot deauthenticate device %s: %s", current.Address, err)
				}

				// Will set a record deleted after 30 seconds that a device can use to reauthenticate
				err = current.SetChallenge()
				if err != nil {
					return fmt.Errorf("failed to set device challenge")
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

				log.Printf("deauthed %s:%s device, reason: %s ", current.Username, current.Address, strings.Join(reasons, ","))

			}
		}

		if current.AssociatedNode != previous.AssociatedNode {
			err := f.UpdateNodeAssociation(current)
			if err != nil {
				return fmt.Errorf("cannot change device node association %s:%s: %s", current.Address, current.Username, err)
			}

			log.Printf("changed device (%s:%s) node association: %s -> %s", current.Address, current.Username, previous.AssociatedNode, current.AssociatedNode)
		}

		// If the authorisation state has changed and is not disabled
		if data.HasDeviceAuthorised(current, previous) {
			err := f.SetAuthorized(current.Address, current.AssociatedNode)

			if err != nil {
				return fmt.Errorf("cannot authorize device %s: %s", current.Address, err)
			}
			log.Println("authorized device: ", current.Address)

		}

	default:
		panic("unknown state")
	}

	return nil
}

func (f *Firewall) userChanges(_ string, et data.EventType, current, previous data.UserModel) error {
	switch et {
	case data.CREATED:
		err := f.AddUser(current.Username)
		if err != nil {
			return fmt.Errorf("cannot create user %s: %s", current.Username, err)
		}
		log.Printf("added user: %q", current.Username)

	case data.DELETED:
		err := f.RemoveUser(current.Username)
		if err != nil {
			return fmt.Errorf("cannot remove user %s: %s", current.Username, err)
		}
		log.Printf("removed user: %q", current.Username)

	case data.MODIFIED:

		if current.Locked != previous.Locked || current.Locked {

			err := f.SetLockAccount(current.Username, current.Locked)
			if err != nil {
				return fmt.Errorf("cannot lock user %s: %s", current.Username, err)
			}
		}

		if current.Mfa != previous.Mfa || current.MfaType != previous.MfaType ||
			!current.Enforcing || types.MFA(current.MfaType) == types.Unset {
			err := f.DeauthenticateAllDevices(current.Username)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate user %s: %s", current.Username, err)
			}
		}

		log.Printf("modified user: %q", current.Username)

	}

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
		log.Printf("refreshed configuration")
	}

	return nil
}

func (f *Firewall) groupChanges(key string, et data.EventType, _, _ any) error {

	keyParts, err := data.SplitKey(2, data.GroupMembershipPrefix, key)
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

		log.Printf("refreshed acls for %q user", username)

	}
	return nil
}
