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

	watchers  []context.CancelFunc
	callbacks WatcherCallbacks[T]

	db interfaces.Watchers

	wait chan bool
}

type AllCallbackFunc[T any] func(key string, eventType data.EventType, newState, previousState T) error

type CallbackFunc[T any] func(key string, newState, previousState T) error

type WatcherCallbacks[T any] struct {
	// Created(...) gets only newly created keys
	Created []CallbackFunc[T]

	// Modified(...) gets changes to existing keys
	Modified []CallbackFunc[T]

	// Deleted(...) only gets deleted keys
	Deleted []CallbackFunc[T]

	// All(...) gets all of the key events
	All AllCallbackFunc[T]
}

type callback[T any] struct {
	t  data.EventType
	cb func(key string, newState, previousState T) error
}

func OnCreate[T any](cb CallbackFunc[T]) callback[T] {
	return callback[T]{
		t:  data.CREATED,
		cb: cb,
	}
}

func OnModification[T any](cb CallbackFunc[T]) callback[T] {
	return callback[T]{
		t:  data.MODIFIED,
		cb: cb,
	}
}

func OnDelete[T any](cb CallbackFunc[T]) callback[T] {
	return callback[T]{
		t:  data.DELETED,
		cb: cb,
	}
}

func Watch[T any](
	db interfaces.Watchers,
	Key string,
	WatchPrefix bool,
	callbacks ...callback[T]) (*Watcher[T], error) {

	var wcbs WatcherCallbacks[T]

	for _, c := range callbacks {
		switch c.t {
		case data.CREATED:
			wcbs.Created = append(wcbs.Created, c.cb)
		case data.MODIFIED:
			wcbs.Modified = append(wcbs.Modified, c.cb)

		case data.DELETED:
			wcbs.Deleted = append(wcbs.Deleted, c.cb)
		}

	}

	return WatchMulti(db, []string{Key}, WatchPrefix, wcbs)
}

func WatchAll[T any](
	db interfaces.Watchers,
	Key string,
	WatchPrefix bool,
	cb AllCallbackFunc[T]) (*Watcher[T], error) {

	return WatchMulti(db, []string{Key}, WatchPrefix, WatcherCallbacks[T]{
		All: cb,
	})
}

// Watch allows you to register a typesafe callback that will be fired when a key, or prefix is modified in etcd
// This callback will be run in a gothread
// Any structure elements that are marked with `sensitive:"yes"` will be zero'd when emitted to the general event log
func WatchStruct[T any](
	db interfaces.Watchers,
	Key string,
	WatchPrefix bool,
	callbacks WatcherCallbacks[T]) (*Watcher[T], error) {

	return WatchMulti(db, []string{Key}, WatchPrefix, callbacks)
}

// WatchMulti allows you to register a typesafe callback that will be fired when a key, or prefix is modified in etcd
// This callback will be run in a gothread
// Any structure elements that are marked with `sensitive:"yes"` will be zero'd when emitted to the general event log
func WatchMulti[T any](db interfaces.Watchers,
	Keys []string,
	WatchPrefix bool,
	callbacks WatcherCallbacks[T]) (*Watcher[T], error) {

	s := &Watcher[T]{
		db:        db,
		callbacks: callbacks,
		wait:      make(chan bool),
	}

	ops := []clientv3.OpOption{clientv3.WithPrevKV()}

	if WatchPrefix {
		ops = append(ops, clientv3.WithPrefix())
	}

	apply := func(cb CallbackFunc[T], e parsedEvent[T]) {
		if cb != nil {
			if err := cb(e.key, e.current, e.previous); err != nil {
				value, _ := json.Marshal(e.current)
				db.RaiseError(fmt.Errorf("applying event failed: %s %s %v, err: %w", e.eventType, e.key, e.current, err), value)
			}
		}
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

					switch e.eventType {
					case data.CREATED:
						for _, createdFuncs := range callbacks.Created {
							apply(createdFuncs, e)
						}

					case data.MODIFIED:
						for _, modifiedFuncs := range callbacks.Modified {

							apply(modifiedFuncs, e)
						}

					case data.DELETED:
						for _, deletedFuncs := range callbacks.Deleted {

							apply(deletedFuncs, e)
						}
					}

					if callbacks.All != nil {
						if err := callbacks.All(e.key, e.eventType, e.current, e.previous); err != nil {
							value, _ := json.Marshal(e.current)
							db.RaiseError(fmt.Errorf("applying all event failed: %s %s %v, err: %w", e.eventType, e.key, e.current, err), value)
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

func (s *Watcher[T]) Wait() {
	<-s.wait
}

func (s *Watcher[T]) Close() error {
	s.Lock()
	defer s.Unlock()

	for _, cancel := range s.watchers {
		cancel()
	}
	clear(s.watchers)

	close(s.wait)

	return nil
}
