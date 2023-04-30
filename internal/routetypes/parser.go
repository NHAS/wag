package routetypes

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	MAX_POLICIES = 128

	ICMP = 1  // Internet Control Message
	TCP  = 6  // Transmission Control
	UDP  = 17 // User Datagram
)

type Rule struct {
	Keys   []Key
	Values []Policy
}

func ParseRules(restrictionType PolicyType, rules []string) (result []Rule, err error) {

	assignedRoutes := map[string]bool{}

	for _, rule := range rules {
		r, err := ParseRule(restrictionType, rule)
		if err != nil {
			return nil, err
		}

		for _, k := range r.Keys {
			if _, ok := assignedRoutes[k.String()]; ok {
				return nil, errors.New("route " + k.String() + " already defined")
			}
			assignedRoutes[k.String()] = true
		}

		result = append(result, r)
	}

	return
}

func AclsToRoutes(rules []string) (routes []string, err error) {

	for _, rule := range rules {
		ruleParts := strings.Fields(rule)
		if len(ruleParts) < 1 {
			return nil, errors.New("could not split correct number of rules")
		}

		keys, err := parseKeys(ruleParts[0])
		if err != nil {
			return rules, errors.New("could not parse address " + ruleParts[0] + " err: " + err.Error())
		}

		for _, k := range keys {
			routes = append(routes, k.String())
		}
	}

	return
}

func ParseRule(restrictionType PolicyType, rule string) (rules Rule, err error) {
	ruleParts := strings.Fields(rule)
	if len(ruleParts) < 1 {
		return rules, errors.New("could not split correct number of rules")
	}

	keys, err := parseKeys(ruleParts[0])
	if err != nil {
		return rules, errors.New("could not parse keys from address " + ruleParts[0] + " err: " + err.Error())
	}

	rules.Keys = keys

	rules.Values = make([]Policy, 0, MAX_POLICIES)

	if len(ruleParts) == 1 {
		// If the user has only defined one address and no ports this counts as an any/any rule

		rules.Values = append(rules.Values, Policy{
			PolicyType: uint16(restrictionType) | SINGLE,
			Proto:      ANY,
			LowerPort:  ANY,
		})

	} else {

		for _, field := range ruleParts[1:] {
			policy, err := parseService(field)
			if err != nil {
				return rules, err
			}

			policy.PolicyType = uint16(restrictionType) | policy.PolicyType

			rules.Values = append(rules.Values, policy)
		}
	}

	if len(rules.Values) > MAX_POLICIES {
		return rules, errors.New("number of policies defined was greather than max")
	}

	rules.Values = rules.Values[:cap(rules.Values)]
	return
}

func parseKeys(address string) (keys []Key, err error) {
	resultingAddresses, err := parseAddress(address)
	if err != nil {
		return nil, err
	}

	for _, ip := range resultingAddresses {

		maskLength, _ := ip.Mask.Size()

		keys = append(keys,
			Key{
				Prefixlen: uint32(maskLength),
				IP:        [4]byte{ip.IP.To4()[0], ip.IP.To4()[1], ip.IP.To4()[2], ip.IP.To4()[3]},
			},
		)
	}

	return
}

func ValidateRules(rules []string) error {
	for _, rule := range rules {
		_, err := ParseRule(PUBLIC, rule)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseService(service string) (Policy, error) {
	parts := strings.Split(service, "/")
	if len(parts) == 1 {
		// are declarations like `icmp` which dont have a port
		switch parts[0] {
		case "icmp":

			return Policy{
				PolicyType: SINGLE,
				Proto:      ICMP,
				LowerPort:  0,
			}, nil

		default:
			return Policy{}, errors.New("malformed port/service declaration: " + service)
		}

	}

	portRange := strings.Split(parts[0], "-")
	proto := strings.ToLower(parts[1])
	if len(portRange) == 1 {
		br, err := parseSinglePort(parts[0], proto)
		return br, err
	}

	return parsePortRange(portRange[0], portRange[1], proto)
}

func parsePortRange(lowerPort, upperPort, proto string) (Policy, error) {
	lowerPortNum, err := strconv.Atoi(lowerPort)
	if err != nil {
		return Policy{}, errors.New("could not convert lower port defintion to number: " + lowerPort)
	}

	upperPortNum, err := strconv.Atoi(upperPort)
	if err != nil {
		return Policy{}, errors.New("could not convert upper port defintion to number: " + upperPort)
	}

	if lowerPortNum > upperPortNum {
		return Policy{}, errors.New("lower port cannot be higher than upper power: lower: " + lowerPort + " upper: " + upperPort)
	}

	switch proto {
	case "any":

		return Policy{
			PolicyType: RANGE,
			Proto:      ANY,

			LowerPort: uint16(lowerPortNum),
			UpperPort: uint16(upperPortNum),
		}, nil

	case "tcp", "udp":

		service := TCP
		if proto == "udp" {
			service = UDP
		}

		return Policy{
			PolicyType: RANGE,

			Proto:     uint16(service),
			LowerPort: uint16(lowerPortNum),
			UpperPort: uint16(upperPortNum),
		}, nil
	}

	return Policy{}, errors.New("unknown service: " + proto)

}

func parseSinglePort(port, proto string) (Policy, error) {
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return Policy{}, errors.New("could not convert port defintion to number: " + port)
	}

	switch proto {
	case "any":

		return Policy{
			PolicyType: SINGLE,
			Proto:      ANY,
			LowerPort:  uint16(portNumber),
		}, nil

	case "tcp", "udp":

		service := TCP
		if proto == "udp" {
			service = UDP
		}

		return Policy{
			PolicyType: SINGLE,
			Proto:      uint16(service),
			LowerPort:  uint16(portNumber),
		}, nil
	}

	return Policy{}, errors.New("unknown service: " + port + "/" + proto)
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
