package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
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

	watchers []context.CancelFunc

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
		db: db,
	}

	ops := []clientv3.OpOption{clientv3.WithPrevKV()}

	if WatchPrefix {
		ops = append(ops, clientv3.WithPrefix())
	}

	for _, key := range Keys {

		ctx, cancel := context.WithCancel(context.Background())

		s.Lock()
		s.watchers = append(s.watchers, cancel)
		s.Unlock()

		output := make(chan parsedEvent[T], 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e, ok := <-output:
					if !ok {
						return
					}

					if err := ResolverFunc(e.key, e.eventType, e.current, e.previous); err != nil {
						value, _ := json.Marshal(e.current)
						db.RaiseError(fmt.Errorf("applying event failed: %s %s %v, err: %w", e.eventType, e.key, e.current, err), value)
					}
				}
			}

		}()

		wc := db.Raw().Watch(ctx, key, ops...)
		go func(wc clientv3.WatchChan) {
			defer cancel()
			for watchEvent := range wc {

				if err := watchEvent.Err(); err != nil {
					db.RaiseError(fmt.Errorf("got watch error key %q: err: %w", key, err), nil)
					return
				}

				for _, event := range watchEvent.Events {

					go func() {

						p, err := parseEvent[T](event)
						if err != nil {

							b, _ := json.MarshalIndent(p.current, "", "    ")
							db.RaiseError(fmt.Errorf("failed to parse event for sending: %w", err), b)
							return
						}

						err = sendEvent(ctx, p, output)
						if err != nil {
							b, _ := json.MarshalIndent(p.current, "", "    ")
							db.RaiseError(err, b)
						}
						db.Write(data.NewGeneralEvent(p.eventType, p.key, &p.current, &p.previous))

					}()

				}
			}
		}(wc)

	}

	return s, nil

}

func sendEvent[T any](ctx context.Context, pe parsedEvent[T], output chan parsedEvent[T]) (err error) {
	select {
	case <-ctx.Done():
		close(output)
		return nil
	default:
		select {
		case output <- pe:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("cluster member is slow to apply changes (>5 seconds), this may result in inconsistent state and indicate high resource usage")
		}

	}
}

func parseEvent[T any](event *clientv3.Event) (p parsedEvent[T], err error) {

	p.key = string(event.Kv.Key)

	switch event.Type {
	case mvccpb.DELETE:
		// when we're in a deleted event the current key is Nil so use the previous key as the "previous"
		p.eventType = data.DELETED
		err = json.Unmarshal(event.PrevKv.Value, &p.current)
		if err != nil {
			return p, fmt.Errorf("failed to unmarshal previous entry for key %q deleted event: %w", p.key, err)
		}

	case mvccpb.PUT:
		p.eventType = data.CREATED
		err = json.Unmarshal(event.Kv.Value, &p.current)
		if err != nil {
			return p, fmt.Errorf("failed to unmarshal current key %q event event: %w", p.key, err)
		}

		if event.IsModify() {
			p.eventType = data.MODIFIED
			err = json.Unmarshal(event.PrevKv.Value, &p.previous)
			if err != nil {
				return p, fmt.Errorf("failed to unmarshal previous key %q previous data: %q err: %w", p.key, event.PrevKv.Value, err)
			}
		}
	default:
		return p, fmt.Errorf("invalid mvccpb type: %q, this is a bug", event.Type)

	}

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
