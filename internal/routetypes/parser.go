package routetypes

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MAX_POLICIES = 128

	ICMP = 1  // Internet Control Message
	TCP  = 6  // Transmission Control
	UDP  = 17 // User Datagram
)

type Rule struct {
	//We may have multiple keys in the instance where a domain with multiple A/AAA records is passed in
	Keys []Key

	NumPolicies int
	Values      []Policy
}

var (
	rwLock      sync.RWMutex
	globalCache = map[string][]Rule{}
)

func hash(mfa, public, deny []string) string {

	sort.Strings(mfa)
	sort.Strings(public)
	sort.Strings(deny)

	b := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(b)
	encoder.Encode(mfa)
	encoder.Encode(public)
	encoder.Encode(deny)

	result := sha1.Sum(b.Bytes())
	return hex.EncodeToString(result[:])
}

func ParseRules(mfa, public, deny []string) (result []Rule, errs []error) {

	cache := map[string]int{}

	parseKey := hash(mfa, public, deny)

	rwLock.RLock()
	if entry, ok := globalCache[parseKey]; ok {
		rwLock.RUnlock()
		return entry, nil

	}
	rwLock.RUnlock()

	// Add

	for _, rule := range mfa {

		r, err := parseRule(0, rule)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for i := range r.Keys {
			if index, ok := cache[r.Keys[i].String()]; ok {
				// Maybe do deduplication here? But I'll resolve this if it ever becomes an issue for someone
				result[index].Values = append(result[index].Values, r.Values...)
				continue
			}

			result = append(result, r)
			cache[r.Keys[i].String()] = len(result) - 1
		}

	}

	for _, rule := range public {
		r, err := parseRule(PUBLIC, rule)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for i := range r.Keys {
			if index, ok := cache[r.Keys[i].String()]; ok {
				// Maybe do deduplication here? But I'll resolve this if it ever becomes an issue for someone
				result[index].Values = append(result[index].Values, r.Values...)
				continue
			}

			result = append(result, r)
			cache[r.Keys[i].String()] = len(result) - 1
		}

	}

	for _, rule := range deny {
		r, err := parseRule(DENY, rule)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for i := range r.Keys {
			if index, ok := cache[r.Keys[i].String()]; ok {
				// Maybe do deduplication here? But I'll resolve this if it ever becomes an issue for someone
				result[index].Values = append(result[index].Values, r.Values...)
				continue
			}

			result = append(result, r)
			cache[r.Keys[i].String()] = len(result) - 1
		}

	}

	for i := range result {
		if len(result[i].Values) > MAX_POLICIES {
			errs = append(errs, errors.New("number of policies defined was greather than max"))
			return nil, errs
		}

		temp := make([]Policy, 0, MAX_POLICIES)
		temp = append(temp, result[i].Values...)

		result[i].NumPolicies = len(result[i].Values)

		result[i].Values = temp[:cap(temp)]
	}

	// Dont add a cache entry if there was an error parsing
	if len(errs) == 0 {
		rwLock.Lock()
		globalCache[parseKey] = result
		rwLock.Unlock()
	}
	return
}

func AclsToRoutes(rules []string) (routes []string, err error) {

	deduplication := map[string]bool{}
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
			_, ok := deduplication[k.String()]
			if ok {
				continue
			}

			deduplication[k.String()] = true
			routes = append(routes, k.String())
		}
	}

	return
}

func parseRule(restrictionType PolicyType, rule string) (rules Rule, err error) {
	ruleParts := strings.Fields(rule)
	if len(ruleParts) < 1 {
		return rules, errors.New("could not split correct number of rules")
	}

	keys, err := parseKeys(ruleParts[0])
	if err != nil {
		return rules, errors.New("could not parse keys from address " + ruleParts[0] + " err: " + err.Error())
	}

	rules.Keys = keys

	rules.Values = []Policy{}

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

	return
}

func parseKeys(address string) (keys []Key, err error) {
	var resultingAddresses []net.IPNet

	resultingAddresses, err = parseAddress(address)
	if err != nil {
		return nil, err
	}

	for _, ip := range resultingAddresses {

		maskLength, _ := ip.Mask.Size()
		keys = append(keys,
			Key{
				Prefixlen: uint32(maskLength),
				IP:        []byte{ip.IP.To4()[0], ip.IP.To4()[1], ip.IP.To4()[2], ip.IP.To4()[3]},
			},
		)
	}

	return
}

func ValidateRules(mfa, public, deny []string) error {
	_, errs := ParseRules(mfa, public, deny)

	if len(errs) == 0 {
		return nil
	}

	str := ""
	for _, err := range errs {
		str += err.Error() + "\n"
	}

	return errors.New(str)
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

type cacheEntry struct {
	dnsTime   time.Time
	addresses []net.IPNet
}

var (
	dnsLock  sync.RWMutex
	dnsCache = map[string]cacheEntry{}
)

func parseAddress(address string) (resultAddresses []net.IPNet, err error) {

	ip := net.ParseIP(address)
	if ip == nil {

		_, cidr, err := net.ParseCIDR(address)
		if err != nil {

			dnsLock.RLock()
			if entries, ok := dnsCache[address]; ok && time.Now().Before(entries.dnsTime.Add(3*time.Second)) {
				dnsLock.RUnlock()
				return entries.addresses, nil
			}
			dnsLock.RUnlock()

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

			dnsLock.Lock()
			dnsCache[address] = cacheEntry{dnsTime: time.Now(), addresses: resultAddresses}
			dnsLock.Unlock()

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
