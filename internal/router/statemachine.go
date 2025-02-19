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
	var err error

	f.listenerKeys.Device, err = data.RegisterEventListener(data.DevicesPrefix, true, f.deviceChanges)
	if err != nil {
		return err
	}

	f.listenerKeys.Membership, err = data.RegisterEventListener(data.GroupMembershipPrefix, true, f.membershipChanges)
	if err != nil {
		return err
	}

	f.listenerKeys.Users, err = data.RegisterEventListener(data.UsersPrefix, true, f.userChanges)
	if err != nil {
		return err
	}

	f.listenerKeys.Acls, err = data.RegisterEventListener(data.AclsPrefix, true, f.aclsChanges)
	if err != nil {
		return err
	}

	f.listenerKeys.Groups, err = data.RegisterEventListener(data.GroupsPrefix, true, f.groupChanges)
	if err != nil {
		return err
	}

	f.listenerKeys.Timeout, err = data.RegisterEventListener(data.InactivityTimeoutKey, true, f.inactivityTimeoutChanges)
	if err != nil {
		return err
	}

	return nil

}

func (f *Firewall) deregisterEventHandlers() {

	eventKeys := []string{
		f.listenerKeys.Device,
		f.listenerKeys.Membership,
		f.listenerKeys.Users,
		f.listenerKeys.Acls,
		f.listenerKeys.Groups,
		f.listenerKeys.Timeout,
	}

	for _, key := range eventKeys {
		err := data.DeregisterEventListener(key)
		if err != nil {
			log.Println("failed to deregister: ", err)
		}
	}
}

func (f *Firewall) inactivityTimeoutChanges(_ string, current, _ int, et data.EventType) error {

	switch et {
	case data.MODIFIED, data.CREATED:
		if err := f.SetInactivityTimeout(current); err != nil {
			return fmt.Errorf("unable to set inactivity timeout: %s", err)
		}
		log.Println("inactivity timeout changed")
	}

	return nil
}

func (f *Firewall) deviceChanges(_ string, current, previous data.Device, et data.EventType) error {

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

		if current.Endpoint.String() != previous.Endpoint.String() && f.IsAuthed(current.Address) {

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

		if f.IsAuthed(current.Address) && current.Attempts > lockout || // If the number of authentication attempts on a device has exceeded the max
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

		if current.AssociatedNode != previous.AssociatedNode {
			err := f.UpdateNodeAssociation(current)
			if err != nil {
				return fmt.Errorf("cannot change device node association %s:%s: %s", current.Address, current.Username, err)
			}

			log.Printf("changed device (%s:%s) node association: %s -> %s", current.Address, current.Username, previous.AssociatedNode, current.AssociatedNode)
		}

		// If the authorisation state has changed and is not disabled
		if current.Authorised != previous.Authorised && !current.Authorised.IsZero() && current.Attempts <= lockout && current.AssociatedNode == previous.AssociatedNode {
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

func (f *Firewall) membershipChanges(key string, _, _ []string, et data.EventType) error {
	username := strings.TrimPrefix(key, data.GroupMembershipPrefix)

	switch et {
	case data.CREATED, data.MODIFIED:
		err := f.RefreshUserAcls(username)
		if err != nil {
			return fmt.Errorf("could not refresh acls: %s", err)
		}

		log.Printf("refreshed acls for user %q", username)
	}

	return nil
}

func (f *Firewall) userChanges(_ string, current, previous data.UserModel, et data.EventType) error {
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

func (f *Firewall) aclsChanges(_ string, _, _ acls.Acl, et data.EventType) error {
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

func (f *Firewall) groupChanges(_ string, current, _ []string, et data.EventType) error {
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:

		for _, username := range current {
			err := f.RefreshUserAcls(username)
			if err != nil {
				return fmt.Errorf("failed to refresh acls for user %s: %s", username, err)
			}
		}

		log.Printf("refreshed acls for %d users", len(current))

	}
	return nil
}
