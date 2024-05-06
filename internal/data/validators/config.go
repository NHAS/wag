package validators

import (
	"errors"
	"net"
)

func ValidExternalAddresses(ExternalAddress string) error {
	if len(ExternalAddress) == 0 {
		return errors.New("invalid ExternalAddress is empty")
	}

	host, _, err := net.SplitHostPort(ExternalAddress)
	if err == nil {
		// If the external address has a port, split it off and use that as the external address to check
		ExternalAddress = host
	}

	if net.ParseIP(ExternalAddress) == nil {

		addresses, err := net.LookupIP(ExternalAddress)
		if err != nil {
			return errors.New("invalid ExternalAddress: " + ExternalAddress + " unable to lookup as domain")
		}

		if len(addresses) == 0 {
			return errors.New("invalid ExternalAddress: " + ExternalAddress + " not IPv4 or IPv6 external addresses found")
		}
	}
	return nil
}
