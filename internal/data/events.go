package data

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"reflect"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/queue"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	DevicesPrefix         = "devices-"
	DeviceChallengePrefix = "devicechallenge-"
	DeviceSessionPrefix   = "devicesession-"

	UsersPrefix           = "users-"
	GroupMembershipPrefix = MembershipKey + "-"
	AclsPrefix            = "wag-acls-"
	GroupsPrefix          = "wag-groups-"
	ConfigPrefix          = "wag-config-"
	AuthenticationPrefix  = "wag-config-authentication-"
	NodeInfo              = "wag/node/"
	NodeErrors            = "wag/node/errors"
)

var (
	lck         sync.RWMutex
	contextMaps = map[string]context.CancelFunc{}

	clusterHealthLck       sync.RWMutex
	clusterHealthListeners = map[string]func(string){}

	EventsQueue = queue.NewQueue[GeneralEvent](40)
	exit        = make(chan bool)
)

func deregisterEventListener(key string) error {
	clusterHealthLck.Lock()
	defer clusterHealthLck.Unlock()
	cancelFunc, ok := contextMaps[key]
	if !ok {
		return fmt.Errorf("event listener was not found: %s", key)
	}

	cancelFunc()

	delete(contextMaps, key)

	return nil
}

// RegisterEventListener allows you to register a callback that will be fired when a key, or prefix is modified in etcd
// This callback will be run in a gothread
// Any structure elements that are marked with `sensitive:"yes"` will be zero'd
func registerEventListener[T any](path string, isPrefix bool, f func(key string, et mvccpb.Event_EventType, empty, modified bool, state T) error) (string, error) {

	options := []clientv3.OpOption{}

	if isPrefix {
		options = append(options, clientv3.WithPrefix())
	}

	key, err := utils.GenerateRandomHex(16)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithCancel(context.Background())
	lck.Lock()
	contextMaps[key] = cancel
	lck.Unlock()

	type Notification struct {
		state     T
		key       string
		eventType mvccpb.Event_EventType
		empty     bool
		modified  bool
	}

	output := make(chan Notification, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case current, ok := <-output:
				if !ok {
					return
				}

				if err := f(current.key, current.eventType, current.empty, current.modified, current.state); err != nil {
					log.Println("applying event failed: ", current.eventType, string(current.key), current.state, "err:", err)
					value, _ := json.Marshal(current.state)
					err = RaiseError(err, value)
					if err != nil {
						log.Println("failed to raise error with cluster: ", err)
						continue
					}
				}

			}

		}
	}()

	wc := etcd.Watch(ctx, path, options...)
	go func(wc clientv3.WatchChan) {
		defer func() {
			cancel()
			close(output)
		}()
		for watchEvent := range wc {

			if err := watchEvent.Err(); err != nil {
				log.Println("got watch error: ", err, path)
				return
			}

			for _, event := range watchEvent.Events {

				go func() {
					var n Notification
					n.key = string(event.Kv.Key)
					n.empty = true
					n.eventType = event.Type
					n.modified = event.IsModify()

					if event.Type != mvccpb.DELETE {
						err := json.Unmarshal(event.Kv.Value, &n.state)
						if err != nil {
							log.Println("unable to unmarshal current type: ", path, string(event.Kv.Value), err)
							return
						}

						n.empty = false
					}

					select {
					case <-ctx.Done():
						return
					case output <- n:
					default:
					}

				}()

			}
		}
	}(wc)

	return key, nil
}

func redact[T any](input T) (redacted []byte) {

	defer func() {
		if e := recover(); e != nil {
			log.Println("redacting panicked: ", e)
		}
	}()

	// Make a copy of the input to avoid modifying the original
	inputValue := reflect.ValueOf(input)
	inputType := inputValue.Type()

	copied := reflect.New(inputType).Elem()
	copied.Set(inputValue)

	if copied.Kind() == reflect.Pointer {
		if copied.IsNil() {
			return nil
		}

		elemType := copied.Elem().Type()
		newElem := reflect.New(elemType).Elem()
		newElem.Set(copied.Elem())
		copied = newElem
	}

	if copied.Kind() == reflect.Struct {
		for i := 0; i < copied.NumField(); i++ {
			field := copied.Field(i)
			fieldType := copied.Type().Field(i)

			// Check for sensitive tag
			if _, isSensitive := fieldType.Tag.Lookup("sensitive"); isSensitive {
				// Set field to zero value if possible
				if field.CanSet() {
					field.Set(reflect.Zero(field.Type()))
				} else {
					log.Printf("cannot redact field %s: field cannot be set", fieldType.Name)
				}
			}
		}
	}

	b, err := json.MarshalIndent(copied.Interface(), "", "    ")
	if err != nil {
		log.Println("could not marshal: ", err)
	}
	return b
}

type GeneralEvent struct {
	Type string    `json:"type"`
	Key  string    `json:"key"`
	Time time.Time `json:"time"`

	State struct {
		Current  string `json:"current"`
		Previous string `json:"previous"`
	} `json:"state"`
}

func NewGeneralEvent[T any](eType EventType, key string, currentState, previousState *T) GeneralEvent {

	return GeneralEvent{
		Type: eType.String(),
		Key:  key,
		Time: time.Now(),
		State: struct {
			Current  string `json:"current"`
			Previous string `json:"previous"`
		}{
			Current:  string(redact(currentState)),
			Previous: string(redact(previousState)),
		},
	}
}

func RegisterClusterHealthListener(f func(status string)) (string, error) {

	key, err := utils.GenerateRandomHex(16)
	if err != nil {
		return "", err
	}

	clusterHealthLck.Lock()
	clusterHealthListeners[key] = f
	clusterHealthLck.Unlock()

	if !etcdServer.Server.IsLearner() {
		// The moment we've registered a new health listener, test the cluster so it gets a callback
		testCluster()
	}

	return key, nil
}

func notifyClusterHealthListeners(event string) {
	clusterHealthLck.RLock()
	defer clusterHealthLck.RUnlock()

	for _, f := range clusterHealthListeners {
		go f(event)
	}
}

func checkClusterHealth() {

	leaderMonitor := time.NewTicker(1 * time.Second)
	go func() {
		for range leaderMonitor.C {
			if etcdServer.Server.Leader() == 0 {

				notifyClusterHealthListeners("electing")
				time.Sleep(etcdServer.Server.Cfg.ElectionTimeout() * 2)

				if etcdServer.Server.Leader() == 0 {
					notifyClusterHealthListeners("dead")
				}
			}
		}
	}()

	clusterMonitor := time.NewTicker(30 * time.Second)
	go func() {
		for range clusterMonitor.C {
			// If we're a learner we cant write to the cluster, so just wait until we're promoted
			if !etcdServer.Server.IsLearner() {
				testCluster()
			}
		}
	}()

	<-exit

	log.Println("etcd server was instructed to terminate")
	leaderMonitor.Stop()
	clusterMonitor.Stop()

}

func testCluster() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	_, err := etcd.Put(ctx, path.Join(NodeInfo, GetServerID().String(), "ping"), time.Now().Format(time.RFC1123Z))
	cancel()
	if err != nil {
		log.Println("unable to write liveness value")
		notifyClusterHealthListeners("dead")
		return
	}

	notifyHealthy()
}

func notifyHealthy() {
	if etcdServer.Server.IsLearner() {
		notifyClusterHealthListeners("learner")
	} else {
		notifyClusterHealthListeners("healthy")
	}
}

type EventError struct {
	NodeID          string    `json:"node_id"`
	ErrorID         string    `json:"error_id"`
	FailedEventData string    `json:"failed_event_data"`
	Error           string    `json:"error"`
	Time            time.Time `json:"time"`
}

func RaiseError(raisedError error, value []byte) (err error) {

	ee := EventError{
		NodeID:          GetServerID().String(),
		FailedEventData: string(value),
		Error:           raisedError.Error(),
		Time:            time.Now(),
	}

	ee.ErrorID, err = utils.GenerateRandomHex(16)
	if err != nil {
		return err
	}

	return set(path.Join(NodeErrors, ee.ErrorID), false, ee)

}

func GetAllErrors() (ret []EventError, err error) {
	response, err := etcd.Get(context.Background(), path.Join(NodeErrors), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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
	_, err := etcd.Delete(context.Background(), path.Join(NodeErrors, errorId))
	return err
}
