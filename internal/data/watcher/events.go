package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/utils"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type parsedEvent[T any] struct {
	key               string
	eventType         data.EventType
	current, previous T
}

type Watcher[T any] struct {
	sync.Mutex

	watchers map[string]context.CancelFunc

	db interfaces.Watchers
}

// Watch allows you to register a typesafe callback that will be fired when a key, or prefix is modified in etcd
// This callback will be run in a gothread
// Any structure elements that are marked with `sensitive:"yes"` will be zero'd when emitted to the general event log
func Watch[T any](
	db interfaces.Watchers,
	Key string,
	WatchPrefix bool,
	ResolverFunc func(key string, eventType data.EventType, newState, previousState T) error) (*Watcher[T], error) {

	return WatchMulti(db, []string{Key}, WatchPrefix, ResolverFunc)
}

// WatchMulti allows you to register a typesafe callback that will be fired when a key, or prefix is modified in etcd
// This callback will be run in a gothread
// Any structure elements that are marked with `sensitive:"yes"` will be zero'd when emitted to the general event log
func WatchMulti[T any](db interfaces.Watchers,
	Keys []string,
	WatchPrefix bool,
	ResolverFunc func(key string, eventType data.EventType, newState, previousState T) error) (*Watcher[T], error) {

	s := &Watcher[T]{
		db:       db,
		watchers: make(map[string]context.CancelFunc),
	}

	ops := []clientv3.OpOption{clientv3.WithPrevKV()}

	if WatchPrefix {
		ops = append(ops, clientv3.WithPrefix())
	}

	for _, key := range Keys {

		ctx, cancel := context.WithCancel(context.Background())

		listenKey, err := utils.GenerateRandomHex(16)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to generate watcher key: %w", err)
		}

		s.watchers[listenKey] = cancel

		output := make(chan parsedEvent[T], 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
				case e, ok := <-output:
					if !ok {
						return
					}

					if err := ResolverFunc(key, e.eventType, e.current, e.previous); err != nil {
						log.Println("applying event failed: ", e.eventType, e.key, e.current, "err:", err)
						value, _ := json.Marshal(e.current)
						err = db.RaiseError(err, value)
						if err != nil {
							log.Println("failed to raise error with cluster: ", err)
						}
					}
				}
			}

		}()

		wc := db.Raw().Watch(ctx, key, ops...)
		go func(wc clientv3.WatchChan) {
			defer cancel()
			for watchEvent := range wc {

				if err := watchEvent.Err(); err != nil {
					log.Println("got watch error: ", err, key)
					return
				}

				for _, event := range watchEvent.Events {

					go func() {
						select {
						case <-ctx.Done():
							close(output)
							return
						default:
							pe, err := parseEvent[T](db, key, event)
							if err != nil {
								log.Println("parsing event failed: ", pe.eventType, key, pe.current, "err:", err)
								value, _ := json.Marshal(pe.current)
								err = db.RaiseError(err, value)
								if err != nil {
									log.Println("failed to raise error with cluster: ", err)
									return
								}
								return
							}

							select {
							case output <- pe:
							case <-time.After(5 * time.Second):
								err = db.RaiseError(errors.New("cluster member is slow to apply changes (>5 seconds), this may result in inconsistent state and indicate high resource usage"), nil)
								if err != nil {
									log.Println("failed to raise error with cluster: ", err)
									return
								}
							}

						}

					}()

				}
			}
		}(wc)

	}

	return s, nil

}

func parseEvent[T any](db interfaces.Watchers, key string, event *clientv3.Event) (p parsedEvent[T], err error) {

	switch event.Type {
	case mvccpb.DELETE:
		// when we're in a deleted event the current key is Nil so use the previous key as the "previous"
		p.eventType = data.DELETED
		err = json.Unmarshal(event.PrevKv.Value, &p.current)
		if err != nil {
			return p, fmt.Errorf("failed to unmarshal previous entry for key %q deleted event: %w", key, err)
		}

	case mvccpb.PUT:
		p.eventType = data.CREATED
		err = json.Unmarshal(event.Kv.Value, &p.current)
		if err != nil {
			return p, fmt.Errorf("failed to unmarshal current key %q event event: %w", key, err)
		}

		if event.IsModify() {
			p.eventType = data.MODIFIED
			err = json.Unmarshal(event.PrevKv.Value, &p.previous)
			if err != nil {
				return p, fmt.Errorf("failed to unmarshal previous key %q previous data: %q err: %w", key, event.PrevKv.Value, err)
			}
		}
	default:
		return p, fmt.Errorf("invalid mvccpb type: %q, this is a bug", event.Type)

	}

	db.Write(data.NewGeneralEvent(p.eventType, key, &p.current, &p.previous))

	return

}

func (s *Watcher[T]) Close() error {
	s.Lock()
	defer s.Unlock()

	for _, cancel := range s.watchers {
		cancel()
	}
	clear(s.watchers)

	return nil
}
