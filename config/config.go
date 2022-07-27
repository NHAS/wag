package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
)

type webserverDetails struct {
	ListenAddress string
	CertPath      string
	KeyPath       string
}

func (wb *webserverDetails) SupportsTLS() bool {
	return len(wb.CertPath) > 0 && len(wb.KeyPath) > 0
}

type Config struct {
	Proxied               bool
	WgDevName             string
	HelpMail              string
	Lockout               int
	ExternalAddress       string
	SessionTimeoutMinutes int
	Webserver             struct {
		Public webserverDetails
		Tunnel webserverDetails
	}
	DatabaseLocation string
	Issuer           string
	VPNRange         *net.IPNet `json:"-"`
	VPNServerAddress net.IP     `json:"-"`
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
