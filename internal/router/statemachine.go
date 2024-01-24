package router

import (
	"log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func handleEvents(erroChan chan<- error) {
	data.RegisterAclsWatcher(aclsChanges)
	data.RegisterClusterHealthWatcher(clusterState(erroChan))
	data.RegisterDeviceWatcher(deviceChanges)
	data.RegisterGroupsWatcher(groupChanges)
	data.RegisterUserWatcher(userChanges)
}

func deviceChanges(device data.BasicEvent[data.Device], state int) {

	log.Printf("state: %d, event: %+v", state, device)

	switch state {
	case data.DELETED:
		err := RemovePeer(device.CurrentValue.Publickey, device.CurrentValue.Address)
		if err != nil {
			log.Println("could not remove peer: ", err)
		}

	case data.CREATED:

		key, _ := wgtypes.ParseKey(device.CurrentValue.Publickey)
		err := AddPeer(key, device.CurrentValue.Username, device.CurrentValue.Address, device.CurrentValue.PresharedKey)
		if err != nil {
			log.Println("error creating peer: ", err)
		}

	case data.MODIFIED:
		if device.CurrentValue.Publickey != device.Previous.Publickey {
			key, _ := wgtypes.ParseKey(device.CurrentValue.Publickey)
			err := ReplacePeer(device.Previous, key)
			if err != nil {
				log.Println(err)
			}
		}

		lockout, err := data.GetLockout()
		if err != nil {
			log.Println("cannot get lockout:", err)
			return
		}

		if (device.CurrentValue.Attempts != device.Previous.Attempts && device.CurrentValue.Attempts > lockout) || // If the number of authentication attempts on a device has exceeded the max
			device.CurrentValue.Endpoint.String() != device.Previous.Endpoint.String() || // If the client ip has changed
			device.CurrentValue.Authorised.IsZero() { // If we've explicitly deauthorised a device
			err := Deauthenticate(device.CurrentValue.Address)
			if err != nil {
				log.Println(err)
			}
		}

		if device.CurrentValue.Authorised != device.Previous.Authorised {
			if !device.CurrentValue.Authorised.IsZero() && device.CurrentValue.Attempts <= lockout {
				err := SetAuthorized(device.CurrentValue.Address, device.CurrentValue.Username)
				if err != nil {
					log.Println(err)
				}
			}
		}

	default:
		panic("unknown state")
	}
}

func userChanges(user data.BasicEvent[data.UserModel], state int) {
	switch state {
	case data.CREATED:
		acls := data.GetEffectiveAcl(user.CurrentValue.Username)
		err := AddUser(user.CurrentValue.Username, acls)
		if err != nil {
			log.Println(err)
		}
	case data.DELETED:
		err := RemoveUser(user.CurrentValue.Username)
		if err != nil {
			log.Println(err)
		}
	case data.MODIFIED:

		if user.CurrentValue.Locked != user.Previous.Locked {

			lock := uint32(1)
			if !user.CurrentValue.Locked {
				lock = 0
			}

			err := SetLockAccount(user.CurrentValue.Username, lock)
			if err != nil {
				log.Println(err)
			}
		}

		if user.CurrentValue.Mfa != user.Previous.Mfa || user.CurrentValue.MfaType != user.Previous.MfaType {
			err := DeauthenticateAllDevices(user.CurrentValue.Username)
			if err != nil {
				log.Println(err)
			}
		}

	}
}

func aclsChanges(aclChange data.TargettedEvent[acls.Acl], state int) {
	switch state {
	case data.CREATED, data.DELETED, data.MODIFIED:
		err := RefreshConfiguration()
		if err != nil {
			log.Println(err)
		}

	}
}

func groupChanges(groupChange data.TargettedEvent[[]string], state int) {
	switch state {
	case data.CREATED, data.DELETED, data.MODIFIED:

		for _, username := range groupChange.Value {
			err := RefreshUserAcls(username)
			if err != nil {
				log.Println(err)
			}
		}

	}
}

func clusterState(errorsChan chan<- error) data.ClusterHealthFunc {

	hasDied := false
	return func(stateText string, state int) {
		log.Println("entered state: ", stateText)

		switch stateText {
		case "dead":
			if !hasDied {
				hasDied = true
				log.Println("Cluster has entered dead state, tearing down: ", hasDied)
				TearDown()
			}
		case "healthy":
			if hasDied {
				err := Setup(errorsChan, true)
				if err != nil {
					log.Println("was unable to return wag member to healthy state, dying: ", err)
					errorsChan <- err
					return
				}

				hasDied = false
			}
		}
	}
}
