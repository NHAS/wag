package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
)

var Config struct {
	WgDevName       string
	ExternalAddress string
	Listen          struct {
		Administration string
		Public         string
		Tunnel         string
	}
	DatabaseLocation string
	Issuer           string
	VPNRange         *net.IPNet `json:"-"`
	MFAAddresses     []string
	CapturedAddreses []string
}

func LoadConfig(path string) error {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	err = json.Unmarshal(configBytes, &Config)
	if err != nil {
		return fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	return nil
}
