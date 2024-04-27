package data

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"sync"
	"time"

	"github.com/NHAS/wag/pkg/queue"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type EventType int

func (ev EventType) String() string {
	switch ev {
	case CREATED:
		return "created"
	case DELETED:
		return "deleted"
	case MODIFIED:
		return "modified"
	}

	return "unknown event type"
}

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
	NodeEvents           = "wag/node/"
	NodeErrors           = "wag/node/errors"
)

var (
	lck         sync.RWMutex
	contextMaps = map[string]context.CancelFunc{}

	clusterHealthLck       sync.RWMutex
	clusterHealthListeners = map[string]func(string){}

	EventsQueue = queue.NewQueue(40)
)

func RegisterEventListener[T any](path string, isPrefix bool, f func(key string, current, previous T, et EventType) error) (string, error) {

	options := []clientv3.OpOption{
		clientv3.WithPrevKV(),
	}

	if isPrefix {
		options = append(options, clientv3.WithPrefix())
	}

	key, err := generateRandomBytes(16)
	if err != nil {
		return "", err
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
					value = event.Kv.Value
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

				go func(key []byte) {
					if err := f(string(key), currentValue, previousValue, state); err != nil {
						log.Println("applying event failed: ", state, currentValue, "err:", err)
						err = RaiseError(GetServerID(), err, value)
						if err != nil {
							log.Println("failed to raise error with cluster: ", err)
							return
						}
						return
					}
					EventsQueue.Write([]byte(fmt.Sprintf("%s[%s]: %s", key, state, string(value))))
				}(event.Kv.Key)

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

	clusterHealthListeners[key] = f

	return key, nil
}

func DeregisterClusterHealthListener(key string) {
	clusterHealthLck.Lock()
	defer clusterHealthLck.Unlock()

	delete(clusterHealthListeners, key)
}

func notifyClusterHealthListeners(event string) {
	clusterHealthLck.RLock()
	defer clusterHealthLck.RUnlock()

	for _, f := range clusterHealthListeners {
		go f(event)
	}
}

func checkClusterHealth() {

	for {

		select {
		case <-etcdServer.Server.LeaderChangedNotify():
			notifyHealthy()

		case <-time.After(1 * time.Second):
			if etcdServer == nil {
				return
			}

			leader := etcdServer.Server.Leader()
			if leader == 0 {
				notifyClusterHealthListeners("electing")
				<-time.After(etcdServer.Server.Cfg.ElectionTimeout() * 2)
				leader = etcdServer.Server.Leader()
				if leader == 0 {
					notifyClusterHealthListeners("dead")
				} else {
					notifyHealthy()
				}
			}

		}

	}
}

func notifyHealthy() {
	if etcdServer.Server.IsLearner() {
		notifyClusterHealthListeners("learner")
	} else {
		notifyClusterHealthListeners("healthy")
	}
}

type EventError struct {
	NodeID          string
	ErrorID         string
	FailedEventData []byte
	Error           string
}

func RaiseError(idHex string, raisedError error, value []byte) (err error) {

	ee := EventError{
		NodeID:          idHex,
		FailedEventData: value,
		Error:           raisedError.Error(),
	}

	ee.ErrorID, err = generateRandomBytes(16)
	if err != nil {
		return err
	}

	eventErrorBytes, _ := json.Marshal(ee)
	_, err = etcd.Put(context.Background(), path.Join(NodeEvents, "errors", ee.ErrorID), string(eventErrorBytes))

	return err

}

func GetAllErrors() (ret []EventError, err error) {
	response, err := etcd.Get(context.Background(), path.Join(NodeEvents, "errors"), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var ee EventError
		err := json.Unmarshal(res.Value, &ee)
		if err != nil {
			return nil, err
		}

		ret = append(ret, ee)
	}

	return ret, nil
}

func ResolveError(errorId string) error {
	_, err := etcd.Delete(context.Background(), path.Join(NodeEvents, "errors", errorId))
	return err
}
