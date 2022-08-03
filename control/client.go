package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	client = http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", controlSocket)
			},
		},
	}
)

func Delete(address string) error {

	form := url.Values{}
	form.Add("address", address)

	response, err := client.Post("http://unix/device/delete", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}

func Block(address string) error {

	form := url.Values{}
	form.Add("address", address)

	response, err := client.Post("http://unix/device/block", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}

func Sessions() (string, error) {

	response, err := client.Get("http://unix/device/sessions")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func FirewallRules() error {

	response, err := client.Get("http://unix/firewall/list")
	if err != nil {
		return err
	}
	defer response.Body.Close()

	result, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if string(result) != "OK!" {
		return errors.New(string(result))
	}

	return nil
}
