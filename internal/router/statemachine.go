package router

import (
	"log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func handleEvents(erroChan chan<- error) {

	_, err := data.RegisterEventListener[data.Device](data.DevicesPrefix, true, deviceChanges)
	if err != nil {
		erroChan <- err
		return
	}

	_, err = data.RegisterEventListener[data.UserModel](data.UsersPrefix, true, userChanges)
	if err != nil {
		erroChan <- err
		return
	}

	_, err = data.RegisterEventListener[acls.Acl](data.AclsPrefix, true, aclsChanges)
	if err != nil {
		erroChan <- err
		return
	}

	_, err = data.RegisterEventListener[[]string](data.GroupsPrefix, true, groupChanges)
	if err != nil {
		erroChan <- err
		return
	}

	_, err = data.RegisterClusterHealthListener(clusterState(erroChan))
	if err != nil {
		erroChan <- err
		return
	}

}

func deviceChanges(key string, current data.Device, previous data.Device, et data.EventType) {

	log.Printf("state: %d, event: %+v", et, current)

	switch et {
	case data.DELETED:
		err := RemovePeer(current.Publickey, current.Address)
		if err != nil {
			log.Println("could not remove peer: ", err)
		}

	case data.CREATED:

		key, _ := wgtypes.ParseKey(current.Publickey)
		err := AddPeer(key, current.Username, current.Address, current.PresharedKey)
		if err != nil {
			log.Println("error creating peer: ", err)
		}

	case data.MODIFIED:
		if current.Publickey != previous.Publickey {
			key, _ := wgtypes.ParseKey(current.Publickey)
			err := ReplacePeer(previous, key)
			if err != nil {
				log.Println(err)
			}
		}

		lockout, err := data.GetLockout()
		if err != nil {
			log.Println("cannot get lockout:", err)
			return
		}

		if (current.Attempts != previous.Attempts && current.Attempts > lockout) || // If the number of authentication attempts on a device has exceeded the max
			current.Endpoint.String() != previous.Endpoint.String() || // If the client ip has changed
			current.Authorised.IsZero() { // If we've explicitly deauthorised a device
			err := Deauthenticate(current.Address)
			if err != nil {
				log.Println(err)
			}
		}

		if current.Authorised != previous.Authorised {
			if !current.Authorised.IsZero() && current.Attempts <= lockout {
				err := SetAuthorized(current.Address, current.Username)
				if err != nil {
					log.Println(err)
				}
			}
		}

	default:
		panic("unknown state")
	}
}

func userChanges(key string, current data.UserModel, previous data.UserModel, et data.EventType) {
	switch et {
	case data.CREATED:
		acls := data.GetEffectiveAcl(current.Username)
		err := AddUser(current.Username, acls)
		if err != nil {
			log.Println(err)
		}
	case data.DELETED:
		err := RemoveUser(current.Username)
		if err != nil {
			log.Println(err)
		}
	case data.MODIFIED:

		if current.Locked != previous.Locked {

			lock := uint32(1)
			if !current.Locked {
				lock = 0
			}

			err := SetLockAccount(current.Username, lock)
			if err != nil {
				log.Println(err)
			}
		}

		if current.Mfa != previous.Mfa || current.MfaType != previous.MfaType {
			err := DeauthenticateAllDevices(current.Username)
			if err != nil {
				log.Println(err)
			}
		}

	}
}

func aclsChanges(key string, current acls.Acl, previous acls.Acl, et data.EventType) {
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:
		err := RefreshConfiguration()
		if err != nil {
			log.Println(err)
		}

	}
}

func groupChanges(key string, current []string, previous []string, et data.EventType) {
	switch et {
	case data.CREATED, data.DELETED, data.MODIFIED:

		for _, username := range current {
			err := RefreshUserAcls(username)
			if err != nil {
				log.Println(err)
			}
		}

	}
}

func clusterState(errorsChan chan<- error) func(string) {

	hasDied := false
	return func(stateText string) {
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
