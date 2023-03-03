package routetypes

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	ICMP = 1  // Internet Control Message
	TCP  = 6  // Transmission Control
	UDP  = 17 // User Datagram
)

var (
	reverseLookup = map[string]int{}
	allRules      []Rule

	rulesLck sync.RWMutex
)

type Rule struct {
	Index int

	Keys []Key
	// Every policy is added for every key.
	// I.e if we have 2 keys, 1.1.1.1 and 1.1.2.2 and three policies then each ip will have 3 polices inserted
	Values []Policy
}

func ResetAndReparseRules(rules []string) (result []Rule, err error) {

	rulesLck.Lock()
	defer rulesLck.Unlock()

	allRules = make([]Rule, len(rules))
	reverseLookup = map[string]int{}

	for _, rule := range rules {
		r, err := parseRule(rule)
		if err != nil {
			return nil, err
		}

		result = append(result, r)
	}

	return
}

func ParseRules(rules []string) (result []Rule, err error) {
	rulesLck.Lock()
	defer rulesLck.Unlock()

	for _, rule := range rules {
		r, err := parseRule(rule)
		if err != nil {
			return nil, err
		}

		result = append(result, r)
	}

	return
}

func ParseRule(rule string) (rules Rule, err error) {
	rulesLck.Lock()
	defer rulesLck.Unlock()

	return parseRule(rule)
}

func parseRule(rule string) (rules Rule, err error) {

	ruleParts := strings.Fields(rule)
	if len(ruleParts) < 1 {
		return rules, errors.New("could not split correct number of rules")
	}

	sort.Strings(ruleParts[1:])
	lookupString := strings.Join(ruleParts, " ")

	if index, ok := reverseLookup[lookupString]; ok {

		return allRules[index], nil
	}

	resultingAddresses, err := parseAddress(ruleParts[0])
	if err != nil {
		return rules, err
	}

	for _, ip := range resultingAddresses {

		maskLength, _ := ip.Mask.Size()

		rules.Keys = append(rules.Keys,
			Key{
				Prefixlen: uint32(maskLength),
				IP:        ip.IP,
			},
		)

		if len(ruleParts) == 1 {
			// If the user has only defined one address and no ports this counts as an any/any rule

			rules.Values = append(rules.Values, Policy{
				PolicyType: SINGLE,
				Proto:      ANY,
				LowerPort:  ANY,
			})

		} else {

			for _, field := range ruleParts[1:] {
				policy, err := parseService(field)
				if err != nil {
					return rules, err
				}

				rules.Values = append(rules.Values, policy)
			}
		}

	}

	rules.Index = len(allRules)
	allRules = append(allRules, rules)
	reverseLookup[lookupString] = rules.Index

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
