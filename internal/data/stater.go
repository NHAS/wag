package data

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type EventType int

func (e EventType) String() string {
	switch e {
	case CREATED:
		return "CREATED"
	case MODIFIED:
		return "MODIFIED"
	case DELETED:
		return "DELETED"
	default:
		return "UNKNOWN"
	}
}

const (
	CREATED EventType = iota
	MODIFIED
	DELETED
)

type Watcher[T any] struct {
	sync.Mutex
	states map[string]T

	listenerKeys []string
}

func WatchMulti[T any](
	Keys []string,
	WatchPrefix bool,
	ResolverFunc func(key string, eventType EventType, newState, previousState T) error) (*Watcher[T], error) {

	s := &Watcher[T]{
		states: make(map[string]T),
	}

	ops := []clientv3.OpOption{}

	if WatchPrefix {
		ops = append(ops, clientv3.WithPrefix())
	}

	// do initial populate
	for _, key := range Keys {
		res, err := etcd.Get(context.Background(), key, ops...)
		if err != nil {
			return nil, err
		}

		for _, res := range res.Kvs {
			var obj T
			err := json.Unmarshal(res.Value, &obj)
			if err != nil {
				return nil, err
			}

			s.states[string(res.Key)] = obj
		}
	}

	for _, key := range Keys {
		listenerKey, err := registerEventListener(key, WatchPrefix, func(key string, et mvccpb.Event_EventType, empty, modified bool, state T) error {
			s.Lock()
			defer s.Unlock()

			if empty && et != mvccpb.DELETE {
				log.Printf("got empty event for key %q: contents: %#v", key, state)
			}

			eventType := CREATED
			previous, hasPrevious := s.states[key]
			if hasPrevious {
				eventType = MODIFIED
			}

			if et == mvccpb.DELETE {
				eventType = DELETED
				if empty {
					if hasPrevious {
						state = previous
					} else {
						return fmt.Errorf("got delete event with empty state, but had no previous value to populate, not executing action on key %q, this is a bug", key)
					}
				}
			}

			go func() {
				p := &previous
				if !hasPrevious {
					p = nil
				}
				EventsQueue.Write(NewGeneralEvent(eventType, key, &state, p))
			}()
			err := ResolverFunc(key, eventType, state, previous)

			s.states[key] = state
			if et == mvccpb.DELETE {
				delete(s.states, key)
			}

			return err
		})
		if err != nil {
			s.Close()
			return nil, err
		}
		s.listenerKeys = append(s.listenerKeys, listenerKey)
	}

	return s, nil

}

func Watch[T any](
	Key string,
	WatchPrefix bool,
	ResolverFunc func(key string, eventType EventType, newState, previousState T) error) (*Watcher[T], error) {

	return WatchMulti([]string{Key}, WatchPrefix, ResolverFunc)
}

func (s *Watcher[T]) Close() error {
	lck.Lock()
	defer lck.Unlock()

	clear(s.states)

	for _, key := range s.listenerKeys {
		deregisterEventListener(key)
	}
	clear(s.listenerKeys)

	return nil
}
