package data

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type EventType int

const (
	CREATED = EventType(iota)
	DELETED
	MODIFIED
)

const (
	DevicesPrefix        = "devices-"
	UsersPrefix          = "users-"
	AclsPrefix           = "wag-acls-"
	GroupsPrefix         = "wag-groups-"
	ConfigPrefix         = "wag-config-"
	AuthenticationPrefix = "wag-config-authentication-"
)

var (
	lck         sync.RWMutex
	contextMaps = map[string]context.CancelFunc{}

	clusterHealthLck sync.RWMutex
	clusterHealth    = map[string]func(string){}
)

func RegisterEventListener[T any](path string, isPrefix bool, f func(key string, current, previous T, et EventType)) (string, error) {

	options := []clientv3.OpOption{
		clientv3.WithPrevKV(),
	}

	if isPrefix {
		options = append(options, clientv3.WithPrefix())
	}

	key, err := generateRandomBytes(16)
	if err != nil {
		return "", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	lck.Lock()
	contextMaps[key] = cancel
	lck.Unlock()

	wc := etcd.Watch(ctx, path, options...)
	go func(wc clientv3.WatchChan) {
		defer cancel()
		for watchEvent := range wc {
			for _, event := range watchEvent.Events {

				var (
					value []byte = event.Kv.Value
					state EventType
				)
				if event.Type == clientv3.EventTypeDelete {
					state = DELETED
					value = event.PrevKv.Value
				} else if event.PrevKv == nil {
					state = CREATED
				} else {
					state = MODIFIED
				}

				var currentValue, previousValue T
				err := json.Unmarshal(value, &currentValue)
				if err != nil {
					log.Println("unable to unmarshal current type: ", path, string(value), err)
					continue
				}

				if event.PrevKv != nil {
					err = json.Unmarshal(event.PrevKv.Value, &previousValue)
					if err != nil {
						log.Println("unable to unmarshal previous type: ", err)
						continue
					}
				}

				go f(string(event.Kv.Key), currentValue, previousValue, state)

			}
		}
	}(wc)

	return key, nil
}

func DeregisterEventListener(key string) {
	lck.Lock()
	defer lck.Unlock()

	if cancel, ok := contextMaps[key]; ok {
		if cancel != nil {
			cancel()
		}
		delete(contextMaps, key)
	}
}

func RegisterClusterHealthListener(f func(status string)) (string, error) {
	clusterHealthLck.Lock()
	defer clusterHealthLck.Unlock()

	key, err := generateRandomBytes(16)
	if err != nil {
		return "", nil
	}

	clusterHealth[key] = f

	return key, nil
}

func DeregisterClusterHealthListener(key string) {
	clusterHealthLck.Lock()
	defer clusterHealthLck.Unlock()

	delete(clusterHealth, key)
}

func notifyClusterHealthListeners(event string) {
	clusterHealthLck.RLock()
	defer clusterHealthLck.RUnlock()

	for _, f := range clusterHealth {
		go f(event)
	}
}

func checkClusterHealth() {

	for {

		select {
		case <-etcdServer.Server.LeaderChangedNotify():
			notfyHealthy()

		case <-time.After(1 * time.Second):
			leader := etcdServer.Server.Leader()
			if leader == 0 {
				notifyClusterHealthListeners("electing")
				<-time.After(etcdServer.Server.Cfg.ElectionTimeout() * 2)
				leader = etcdServer.Server.Leader()
				if leader == 0 {
					notifyClusterHealthListeners("dead")
				} else {
					notfyHealthy()
				}
			}

		}

	}
}

func notfyHealthy() {
	if etcdServer.Server.IsLearner() {
		notifyClusterHealthListeners("learner")
	} else {
		notifyClusterHealthListeners("healthy")
	}
}
