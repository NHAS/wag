package router

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func handleEvents(errorChan chan<- error) {

	_, err := data.RegisterEventListener(data.DevicesPrefix, true, deviceChanges)
	if err != nil {
		errorChan <- err
		return
	}

	_, err = data.RegisterEventListener(data.GroupMembershipPrefix, true, membershipChanges)
	if err != nil {
		errorChan <- err
		return
	}

	_, err = data.RegisterEventListener(data.UsersPrefix, true, userChanges)
	if err != nil {
		errorChan <- err
		return
	}

	_, err = data.RegisterEventListener(data.AclsPrefix, true, aclsChanges)
	if err != nil {
		errorChan <- err
		return
	}

	_, err = data.RegisterEventListener(data.GroupsPrefix, true, groupChanges)
	if err != nil {
		errorChan <- err
		return
	}

	_, err = data.RegisterEventListener(data.InactivityTimeoutKey, true, inactivityTimeoutChanges)
	if err != nil {
		errorChan <- err
		return
	}

}

func inactivityTimeoutChanges(_ string, current, _ int, et data.EventType) error {

	switch et {
	case data.MODIFIED, data.CREATED:
		if err := SetInactivityTimeout(current); err != nil {
			return fmt.Errorf("unable to set inactivity timeout: %s", err)
		}
		log.Println("inactivity timeout changed")
	}

	return nil
}

func deviceChanges(_ string, current, previous data.Device, et data.EventType) error {

	switch et {
	case data.DELETED:
		err := RemovePeer(current.Publickey, current.Address)
		if err != nil {
			return fmt.Errorf("unable to remove peer: %s: err: %s", current.Address, err)
		}
		log.Println("removed peer: ", current.Address)

	case data.CREATED:

		key, _ := wgtypes.ParseKey(current.Publickey)
		err := AddPeer(key, current.Username, current.Address, current.PresharedKey, uint64(current.AssociatedNode))
		if err != nil {
			return fmt.Errorf("unable to create peer: %s: err: %s", current.Address, err)
		}

		log.Println("added peer: ", current.Address)

	case data.MODIFIED:
		if current.Publickey != previous.Publickey {
			key, _ := wgtypes.ParseKey(current.Publickey)
			err := ReplacePeer(previous, key)
			if err != nil {
				return fmt.Errorf("failed to replace peer pub key: %s", err)
			}
			log.Println("replaced peer public key: ", current.Address)
		}

		lockout, err := data.GetLockout()
		if err != nil {
			return fmt.Errorf("cannot get lockout: %s", err)
		}

		if current.Endpoint.String() != previous.Endpoint.String() {

			log.Printf("challenging %s:%s device, as endpoint changed: %s -> %s", current.Username, current.Address, current.Endpoint.String(), previous.Endpoint.String())
			// Will take at most 4 seconds

			attempts := 0
			for ; attempts < 3; attempts++ {
				err = Verifier.Challenge(current.Address)
				if err != nil {
					time.Sleep(1 * time.Second)
				}
			}

			if attempts >= 3 {
				log.Printf("%s:%s failed to pass websockets challenge: %s", current.Username, current.Address, err)
				err := Deauthenticate(current.Address)
				if err != nil {
					return fmt.Errorf("cannot deauthenticate device %s: %s", current.Address, err)
				}
			} else {
				log.Printf("%s:%s device succeeded challenge", current.Username, current.Address)

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

			err := Deauthenticate(current.Address)
			if err != nil {
				return fmt.Errorf("cannot deauthenticate device %s: %s", current.Address, err)
			}

			log.Printf("deauthed %s:%s device, reason: %s ", current.Username, current.Address, strings.Join(reasons, ","))

		}

		if current.AssociatedNode != previous.AssociatedNode {
			err := UpdateNodeAssociation(current)
			if err != nil {
				return fmt.Errorf("cannot change device node association %s:%s: %s", current.Address, current.Username, err)
			}

			log.Printf("changed device (%s:%s) node association: %s -> %s", current.Address, current.Username, previous.AssociatedNode, current.AssociatedNode)
		}

		// If the authorisation state has changed and is not disabled
		if current.Authorised != previous.Authorised && !current.Authorised.IsZero() {
			if current.Attempts <= lockout && current.AssociatedNode == previous.AssociatedNode {
				err := SetAuthorized(current.Address, current.Username, uint64(current.AssociatedNode))
				if err != nil {
					return fmt.Errorf("cannot authorize device %s: %s", current.Address, err)
				}
				log.Println("authorized device: ", current.Address)
			}
		}

	default:
		panic("unknown state")
	}

	return nil
}

func membershipChanges(key string, _, _ []string, et data.EventType) error {
	username := strings.TrimPrefix(key, data.GroupMembershipPrefix)

	switch et {
	case data.CREATED, data.MODIFIED:
		err := RefreshUserAcls(username)
		if err != nil {
			log.Printf("failed to refresh acls for user %s: %s", username, err)
			return fmt.Errorf("could not refresh acls: %s", err)
		}
	}

	return nil
}

func userChanges(_ string, current, previous data.UserModel, et data.EventType) error {
	switch et {
	case data.CREATED:
		newUserAcls := data.GetEffectiveAcl(current.Username)
		err := AddUser(current.Username, newUserAcls)
		if err != nil {
			log.Printf("cannot create user %s: %s", current.Username, err)
			return fmt.Errorf("cannot create user %s: %s", current.Username, err)
		}
	case data.DELETED:
		err := RemoveUser(current.Username)
		if err != nil {
			log.Printf("cannot remove user %s: %s", current.Username, err)
			return fmt.Errorf("cannot remove user %s: %s", current.Username, err)
		}
	case data.MODIFIED:

		if current.Locked != previous.Locked || current.Locked {

			lock := uint32(1)
			if !current.Locked {
				lock = 0
			}

			err := SetLockAccount(current.Username, lock)
			if err != nil {
				log.Printf("cannot lock user %s: %s", current.Username, err)
				return fmt.Errorf("cannot lock user %s: %s", current.Username, err)
			}
		}

		if current.Mfa != previous.Mfa || current.MfaType != previous.MfaType ||
			!current.Enforcing || types.MFA(current.MfaType) == types.Unset {
			err := DeauthenticateAllDevices(current.Username)
			if err != nil {
				log.Printf("cannot deauthenticate user %s: %s", current.Username, err)
				return fmt.Errorf("cannot deauthenticate user %s: %s", current.Username, err)
			}
		}

	}

	return nil
}

func aclsChanges(_ string, _, _ acls.Acl, et data.EventType) error {
	// TODO refresh the users that the acl applies to as a potential performance improvement
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:
		err := RefreshConfiguration()
		if err != nil {
			return fmt.Errorf("failed to refresh configuration: %s", err)
		}

	}

	return nil
}

func groupChanges(_ string, current, _ []string, et data.EventType) error {
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:

		for _, username := range current {
			err := RefreshUserAcls(username)
			if err != nil {
				return fmt.Errorf("failed to refresh acls for user %s: %s", username, err)
			}
		}

	}
	return nil
}
