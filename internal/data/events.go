package data

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/acls"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	CREATED = iota
	DELETED
	MODIFIED
)

type BasicEvent[T any] struct {
	Key          string
	CurrentValue T
	Previous     T
}

type TargettedEvent[T any] struct {
	Key     string
	Effects string
	Value   T
}

type WatcherFuncType[T any] interface {
	~func(data T, state int)
}

type (
	DeviceChangesFunc func(BasicEvent[Device], int)
	UserChangesFunc   func(BasicEvent[UserModel], int)

	AclChangesFunc   func(TargettedEvent[acls.Acl], int)
	GroupChangesFunc func(TargettedEvent[[]string], int)

	ClusterHealthFunc func(state string, dead int)
)

var (
	deviceWatchers        []DeviceChangesFunc
	usersWatchers         []UserChangesFunc
	aclsWatchers          []AclChangesFunc
	groupsWatchers        []GroupChangesFunc
	clusterHealthWatchers []ClusterHealthFunc

	lck sync.RWMutex
)

func addWatcher[I any, T WatcherFuncType[I]](watcher T, existingWatches *[]T) {
	lck.Lock()
	*existingWatches = append(*existingWatches, watcher)
	lck.Unlock()
}

func execWatchers[I any, T WatcherFuncType[I]](watchers []T, data I, state int) {
	lck.RLock()

	log.Println(len(watchers), data)
	for _, watcher := range watchers {
		go watcher(data, state)
	}

	lck.RUnlock()
}

func RegisterDeviceWatcher(fnc DeviceChangesFunc) {
	addWatcher(fnc, &deviceWatchers)
}

func RegisterUserWatcher(fnc UserChangesFunc) {
	addWatcher(fnc, &usersWatchers)
}

func RegisterAclsWatcher(fnc AclChangesFunc) {
	addWatcher(fnc, &aclsWatchers)
}

func RegisterGroupsWatcher(fnc GroupChangesFunc) {
	addWatcher(fnc, &groupsWatchers)
}

func RegisterClusterHealthWatcher(fnc ClusterHealthFunc) {
	addWatcher(fnc, &clusterHealthWatchers)
}

func watchEvents() {
	wc := etcd.Watch(context.Background(), "", clientv3.WithPrefix(), clientv3.WithPrevKV())
	for watchEvent := range wc {
		for _, event := range watchEvent.Events {

			var (
				value []byte = event.Kv.Value
				state int
			)
			if event.Type == clientv3.EventTypeDelete {
				state = DELETED
				value = event.PrevKv.Value
			} else if event.PrevKv == nil {
				state = CREATED
			} else {
				state = MODIFIED
			}

			switch {
			case bytes.HasPrefix(event.Kv.Key, []byte("devices-")):

				be, err := makeBasicEvent[Device](event)
				if err != nil {
					log.Println("unable to make basic device event: ", err)
					continue
				}

				execWatchers(deviceWatchers, be, state)

			case bytes.HasPrefix(event.Kv.Key, []byte("users-")):

				be, err := makeBasicEvent[UserModel](event)
				if err != nil {
					log.Println("unable to make basic user event: ", err)
					continue
				}

				execWatchers(usersWatchers, be, state)
			case bytes.HasPrefix(event.Kv.Key, []byte("wag-acls-")):

				var a acls.Acl
				err := json.Unmarshal(value, &a)
				if err != nil {
					log.Println("Got an event for a acls that I could not decode: ", err)
					continue
				}

				execWatchers(aclsWatchers, TargettedEvent[acls.Acl]{Effects: string(bytes.TrimPrefix(event.Kv.Key, []byte("wag-acls-"))), Key: string(event.Kv.Key), Value: a}, state)
			case bytes.HasPrefix(event.Kv.Key, []byte("wag-groups-")):

				var groupMembers []string
				err := json.Unmarshal(value, &groupMembers)
				if err != nil {
					log.Println("Got an event for a group members that I could not decode: ", err)
					continue

				}
				execWatchers(groupsWatchers,
					TargettedEvent[[]string]{
						Effects: string(bytes.TrimPrefix(event.Kv.Key, []byte("wag-groups-"))),
						Key:     string(event.Kv.Key),
						Value:   groupMembers,
					}, state)
			default:
				continue
			}

		}

	}
}

func makeBasicEvent[T any](event *clientv3.Event) (BasicEvent[T], error) {
	var d T
	err := json.Unmarshal(event.Kv.Value, &d)
	if err != nil {
		return BasicEvent[T]{}, err
	}

	be := BasicEvent[T]{
		CurrentValue: d,
		Key:          string(event.Kv.Key),
	}

	if event.PrevKv != nil {
		err = json.Unmarshal(event.PrevKv.Value, &be.Previous)
		if err != nil {
			return BasicEvent[T]{}, err
		}
	}

	return be, nil
}

func checkClusterHealth() {

	for {

		select {
		case <-etcdServer.Server.LeaderChangedNotify():
			execWatchers(clusterHealthWatchers, "changed", 0)
			leader := etcdServer.Server.Leader()
			if leader == 0 {
				execWatchers(clusterHealthWatchers, "electing", 0)
				<-time.After(etcdServer.Server.Cfg.ElectionTimeout() * 2)
				leader = etcdServer.Server.Leader()
			}

			if leader != 0 {
				execWatchers(clusterHealthWatchers, "healthy", 0)
			} else {
				execWatchers(clusterHealthWatchers, "dead", 0)
			}

		}

	}
}
