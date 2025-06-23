package data

import (
	"encoding/json"
	"log"
	"reflect"
	"time"
)

const (
	CREATED EventType = iota
	MODIFIED
	DELETED
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

func (d *database) Write(e GeneralEvent) error {
	_, err := d.eventsQueue.Write(e)
	return err
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
		return nil
	}
	return b
}
