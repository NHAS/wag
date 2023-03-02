package routetypes

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	ICMP = 1  // Internet Control Message
	TCP  = 6  // Transmission Control
	UDP  = 17 // User Datagram
)

type BinaryRule struct {
	Key   []byte
	Value []byte
	IP    net.IP
}

func ParseRules(rules []string) (result []BinaryRule, err error) {

	for _, rule := range rules {
		r, err := ParseRule(rule)
		if err != nil {
			return nil, err
		}

		result = append(result, r...)
	}

	return
}

func ParseRule(rule string) (rules []BinaryRule, err error) {

	ruleParts := strings.Fields(rule)
	if len(ruleParts) < 1 {
		return nil, errors.New("could not split correct number of rules")
	}

	resultingAddresses, err := parseAddress(ruleParts[0])
	if err != nil {
		return nil, err
	}

	for _, ip := range resultingAddresses {

		maskLength, _ := ip.Mask.Size()

		if len(ruleParts) == 1 {
			// If the user has only defined one address and no ports this counts as an any/any rule

			key := Key{
				Prefixlen: 64 + uint32(maskLength),
				RuleType:  ANY,
				IP:        ip.IP,
			}

			val := Any{
				Proto: ANY,
				Port:  ANY,
			}

			rules = append(rules, BinaryRule{IP: ip.IP, Key: key.Bytes(), Value: val.Bytes()})

		} else {
			for _, field := range ruleParts[1:] {
				br, err := parseService(ip.IP, uint32(maskLength), field)
				if err != nil {
					return nil, err
				}

				rules = append(rules, br)

			}
		}

	}

	return
}

func ValidateRules(rules []string) error {
	for _, rule := range rules {
		_, err := ParseRule(rule)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseService(ip net.IP, maskLength uint32, service string) (BinaryRule, error) {
	parts := strings.Split(service, "/")
	if len(parts) == 1 {
		// are declarations like `icmp` which dont have a port
		switch parts[0] {
		case "icmp":

			key := Key{
				Prefixlen: 64 + maskLength,
				RuleType:  ANY,
				IP:        ip,
			}

			val := Any{
				Proto: ICMP,
				Port:  1,
			}

			return BinaryRule{IP: ip, Key: key.Bytes(), Value: val.Bytes()}, nil

		default:
			return BinaryRule{}, errors.New("malformed port/service declaration: " + service)
		}

	}

	portRange := strings.Split(parts[0], "-")
	proto := strings.ToLower(parts[1])
	if len(portRange) == 1 {
		br, err := parseSinglePort(ip, maskLength, parts[0], proto)
		return br, err
	}

	return parsePortRange(ip, maskLength, portRange[0], portRange[1], proto)
}

func parsePortRange(ip net.IP, maskLength uint32, lowerPort, upperPort, proto string) (BinaryRule, error) {
	lowerPortNum, err := strconv.Atoi(lowerPort)
	if err != nil {
		return BinaryRule{}, errors.New("could not convert lower port defintion to number: " + lowerPort)
	}

	upperPortNum, err := strconv.Atoi(upperPort)
	if err != nil {
		return BinaryRule{}, errors.New("could not convert upper port defintion to number: " + upperPort)
	}

	if lowerPortNum > upperPortNum {
		return BinaryRule{}, errors.New("lower port cannot be higher than upper power: lower: " + lowerPort + " upper: " + upperPort)
	}

	switch proto {
	case "any":

		key := Key{
			Prefixlen: 64 + maskLength,
			RuleType:  RANGE,
			IP:        ip,
		}

		val := Range{
			Proto:     ANY,
			LowerPort: uint16(lowerPortNum),
			UpperPort: uint16(upperPortNum),
		}

		return BinaryRule{IP: ip, Key: key.Bytes(), Value: val.Bytes()}, nil

	case "tcp", "udp":

		service := TCP
		if proto == "udp" {
			service = UDP
		}

		key := Key{
			Prefixlen: 64 + maskLength,
			RuleType:  RANGE,
			IP:        ip,
		}

		val := Range{
			Proto:     uint16(service),
			LowerPort: uint16(lowerPortNum),
			UpperPort: uint16(upperPortNum),
		}

		return BinaryRule{IP: ip, Key: key.Bytes(), Value: val.Bytes()}, nil
	}

	return BinaryRule{}, errors.New("unknown service: " + proto)

}

func parseSinglePort(ip net.IP, maskLength uint32, port, proto string) (BinaryRule, error) {
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return BinaryRule{}, errors.New("could not convert port defintion to number: " + port)
	}

	switch proto {
	case "any":

		key := Key{
			Prefixlen: 64 + maskLength,
			RuleType:  ANY,
			IP:        ip,
		}

		val := Any{
			Proto: 0,
			Port:  uint16(portNumber),
		}

		return BinaryRule{IP: ip, Key: key.Bytes(), Value: val.Bytes()}, nil

	case "tcp", "udp":

		service := TCP
		if proto == "udp" {
			service = UDP
		}

		key := Key{
			Prefixlen: 64 + maskLength,
			RuleType:  SINGLE,
			Protocol:  uint16(service),
			Port:      uint16(portNumber),
			IP:        ip,
		}

		return BinaryRule{IP: ip, Key: key.Bytes(), Value: make([]byte, 8)}, nil
	}

	return BinaryRule{}, errors.New("unknown service: " + port + "/" + proto)
}

func parseAddress(address string) (resultAddresses []net.IPNet, err error) {

	ip := net.ParseIP(address)
	if ip == nil {

		_, cidr, err := net.ParseCIDR(address)
		if err != nil {

			//If we suspect this is a domain
			addresses, err := net.LookupIP(address)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve address from: %s", address)
			}

			if len(addresses) == 0 {
				return nil, fmt.Errorf("no addresses for %s", address)
			}

			addedSomething := false
			for _, addr := range addresses {
				if addr.To4() != nil {
					addedSomething = true
					resultAddresses = append(resultAddresses, net.IPNet{IP: addr.To4(), Mask: net.IPv4Mask(255, 255, 255, 255)})
				}
			}

			if !addedSomething {
				return nil, fmt.Errorf("no addresses for domain %s were added, potentially because they were all ipv6 which is unsupported", address)
			}

			return resultAddresses, nil
		}

		return []net.IPNet{*cidr}, nil
	}

	// /32
	return []net.IPNet{
		{
			IP:   ip.To4(),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}, nil
}
