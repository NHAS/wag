package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
)

type Config struct {
	Proxied               bool
	WgDevName             string
	Lockout               int
	ExternalAddress       string
	SessionTimeoutMinutes int
	Listen                struct {
		Public string
		Tunnel string
	}
	DatabaseLocation string
	Issuer           string
	VPNRange         *net.IPNet `json:"-"`
	Routes           struct {
		AuthRequired []string
		Public       []string
	}
}

func New(path string) (Config, error) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	var c Config
	err = json.Unmarshal(configBytes, &c)
	if err != nil {
		return Config{}, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	return c, nil
}
