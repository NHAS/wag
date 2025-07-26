package watcher

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
)

var db interfaces.Database

type testStruct struct {
	Test string
}

func TestWatcher(t *testing.T) {

	const key = "wag-test-key"

	output := make(chan parsedEvent[testStruct], 3)
	w, err := Watch(db, key, false,

		OnCreate(func(key string, newState, previousState testStruct) error {
			pe := parsedEvent[testStruct]{
				key:       key,
				eventType: data.CREATED,
				current:   newState,
				previous:  previousState,
			}
			output <- pe

			return nil
		}),
		OnModification(func(key string, newState, previousState testStruct) error {
			pe := parsedEvent[testStruct]{
				key:       key,
				eventType: data.MODIFIED,
				current:   newState,
				previous:  previousState,
			}
			output <- pe

			return nil
		}),
		OnDelete(func(key string, newState, previousState testStruct) error {
			pe := parsedEvent[testStruct]{
				key:       key,
				eventType: data.DELETED,
				current:   newState,
				previous:  previousState,
			}
			output <- pe

			return nil
		}),
	)

	if err != nil {
		t.Fatal(err)
	}

	if len(w.watchers) != 1 {
		t.Fatal("number of watchers was not = 1 when using single registration")
	}

	data.Set(db.Raw(), key, true, testStruct{
		Test: "floop",
	})

	data.Set(db.Raw(), key, true, testStruct{
		Test: "Shoop",
	})

	_, err = db.Raw().Delete(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}

	// CREATED
	p := <-output
	if p.eventType != data.CREATED {
		t.Fatal("expected key to be created was instead: ", p)
	}

	if p.current.Test != "floop" {
		t.Fatal("incorrect contents of current key: ", p.current.Test)
	}

	if p.previous.Test != "" {
		t.Fatal("previous contents should be empty")
	}

	// MODIFIED
	p = <-output
	if p.eventType != data.MODIFIED {
		t.Fatal("expected key to be modified was instead: ", p.eventType)
	}

	if p.current.Test != "Shoop" {
		t.Fatal("incorrect contents of current key: ", p.current.Test)
	}

	if p.previous.Test != "floop" {
		t.Fatal("previous contents should be floop")
	}

	// DELETED
	p = <-output
	if p.eventType != data.DELETED {
		t.Fatal("expected key to be deleted was instead: ", p.eventType)
	}

	if p.current.Test != "Shoop" {
		t.Fatal("incorrect contents of current key: ", p.current.Test)
	}

	if p.previous.Test != "" {
		t.Fatal("previous contents should be empty on delete")
	}

	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

}

func TestMain(m *testing.M) {

	if err := config.Load("../../config/testing_config2.json"); err != nil {
		log.Println("failed to load config: ", err)
		os.Exit(1)
	}

	var err error
	db, err = data.Load("", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	os.Exit(m.Run())

}
