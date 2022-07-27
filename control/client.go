package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

func message(m msg) (result, error) {
	con, err := net.Dial("unix", controlSocket)
	r := result{}
	if err != nil {
		return r, err
	}

	results, err := json.Marshal(&m)
	if err != nil {
		return r, err
	}

	_, err = con.Write(results)
	if err != nil {
		return r, err
	}

	err = json.NewDecoder(con).Decode(&r)

	return r, err
}

func Block(address string) error {

	r, err := message(msg{
		Type: "block",
		Arg:  address,
	})
	if err != nil {
		return err
	}

	if r.Type != "OK" {
		return fmt.Errorf("Unable to block device: %s", r.Text)
	}

	return nil
}

func Sessions() (string, error) {
	r, err := message(msg{
		Type: "sessions",
	})
	if err != nil {
		return "", err
	}

	if r.Type != "OK" {
		return "", errors.New(r.Text)
	}

	return r.Text, nil
}
