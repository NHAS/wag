package routetypes

import (
	"fmt"
	"net"
	"testing"
)

func checkKey(reality Key, expectedKey Key) error {

	if !net.IP.Equal(reality.AsIPv4(), expectedKey.AsIPv4()) {
		return fmt.Errorf("key had incorrect ip: expected: %s got: %s", expectedKey.IP, reality.IP)
	}

	if reality.Prefixlen != expectedKey.Prefixlen {
		return fmt.Errorf("key had incorrect prefix length, should be %d, was: %d", expectedKey.Prefixlen, reality.Prefixlen)
	}

	return nil
}

func checkPolicy(reality Policy, expectedValue Policy) error {

	if !reality.Is(PolicyType(expectedValue.PolicyType)) {
		return fmt.Errorf("value type was not %s, was: %s", expectedValue, reality)
	}

	if reality.LowerPort != expectedValue.LowerPort {
		return fmt.Errorf("value lower port was not %d, was: %d", expectedValue.LowerPort, reality.LowerPort)
	}

	if reality.UpperPort != expectedValue.UpperPort {
		return fmt.Errorf("value upper port was not %d, was: %d", expectedValue.UpperPort, reality.UpperPort)
	}

	if reality.Proto != expectedValue.Proto {
		return fmt.Errorf("value proto was not %d, was: %d", expectedValue.Proto, reality.Proto)
	}

	return nil
}

func TestParseEasyRules(t *testing.T) {

	expected := Key{
		IP:        []byte{1, 1, 1, 1},
		Prefixlen: 32,
	}

	expectedValue := Policy{
		PolicyType: SINGLE,
		Proto:      ANY,
		LowerPort:  ANY,
	}

	br, err := parseRule(0, "1.1.1.1")
	if err != nil {
		t.Fatal("failed to parse 1.1.1.1", err)
	}

	if err := checkKey(br.Keys[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br.Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	br, err = parseRule(0, "1.1.1.1/32")
	if err != nil {
		t.Fatal("failed to parse 1.1.1.1/32", err)
	}

	if err := checkKey(br.Keys[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br.Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}
}

func TestAclToRoute(t *testing.T) {
	acls := []string{"1.1.1.1", "5.5.5.0/16", "2.2.2.2 80/tcp 100-102/udp"}

	routes, err := AclsToRoutes(acls)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 3 {
		t.Fatal("number of routes produced from acls to routes incorrect")
	}

	if routes[0] != "1.1.1.1/32" {
		t.Fatal("Expected: 1.1.1.1/32 got ", routes[0])
	}

	if routes[1] != "5.5.0.0/16" {
		t.Fatal("Expected: 5.5.0.0/16 got ", routes[1])
	}

	if routes[2] != "2.2.2.2/32" {
		t.Fatal("Expected: 2.2.2.2/32 got ", routes[2])
	}

}

func TestParseSimpleSingles(t *testing.T) {
	br, err := parseRule(0, "1.2.1.2 43/tcp 23/udp icmp 55/any")
	if err != nil {
		t.Fatal("failed to parse 1.2.1.2", err)
	}

	if len(br.Keys) != 1 {
		t.Fatal("expected to define 1 key got: ", len(br.Keys))

	}

	if len(br.Values) != 4 {
		t.Fatal("expected to define 4 policies got: ", len(br.Values))
	}

	expectedKey := Key{
		Prefixlen: 32,
		IP:        []byte{1, 2, 1, 2},
	}

	expectedValues := []Policy{
		{
			PolicyType: SINGLE,
			Proto:      TCP,
			LowerPort:  43,
		},
		{
			PolicyType: SINGLE,
			Proto:      UDP,
			LowerPort:  23,
		},
		{
			PolicyType: SINGLE,
			Proto:      ICMP,
			LowerPort:  0,
		},
		{
			PolicyType: SINGLE,
			Proto:      0,
			LowerPort:  55,
		},
	}

	for _, policy := range br.Values {
		if len(policy.Bytes()) != 8 {
			t.Fatal("policy generated was not 8 bytes")
		}
	}

	if err := checkKey(br.Keys[0], expectedKey); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(br.Values); i++ {
		found := false
		for _, v := range expectedValues {

			if err := checkPolicy(br.Values[i], v); err != nil {
				continue
			}

			found = true
			break
		}

		if !found {
			t.Fatal("did not find rule in set: ", br.Values[i].PolicyType)
		}

	}

}

func TestParsePortRange(t *testing.T) {
	br, err := parseRule(0, "1.3.1.3 43-100/tcp")
	if err != nil {
		t.Fatal("failed to parse 1.3.1.3", err)
	}

	if len(br.Keys) != 1 {
		t.Fatal("expected to define 1 key got: ", len(br.Keys))
	}

	if len(br.Values) != 1 {
		t.Fatal("expected to define 1 policies for key got: ", len(br.Values))
	}

	expected := Key{
		Prefixlen: 32,
		IP:        []byte{1, 3, 1, 3},
	}

	expectedValue := Policy{
		PolicyType: RANGE,
		LowerPort:  43,
		UpperPort:  100,
		Proto:      TCP,
	}

	if err := checkKey(br.Keys[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br.Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	br, err = parseRule(0, "1.4.1.4 43-100/any 55/tcp 66/udp")
	if err != nil {
		t.Fatal("failed to parse 1.4.1.4", err)
	}

	expected = Key{
		Prefixlen: 32,
		IP:        []byte{1, 4, 1, 4},
	}

	expectedValue = Policy{
		PolicyType: RANGE,
		LowerPort:  43,
		UpperPort:  100,
		Proto:      ANY,
	}

	if err := checkKey(br.Keys[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br.Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	expectedValue = Policy{
		PolicyType: SINGLE,
		LowerPort:  55,
		Proto:      TCP,
	}

	if err := checkPolicy(br.Values[1], expectedValue); err != nil {
		t.Fatal(err)
	}

	expectedValue = Policy{
		PolicyType: SINGLE,
		LowerPort:  66,
		Proto:      UDP,
	}

	if err := checkPolicy(br.Values[2], expectedValue); err != nil {
		t.Fatal(err)
	}

}

func TestParseDomainRules(t *testing.T) {
	_, err := parseRule(0, "google.com 443/tcp")
	if err != nil {
		t.Fatal("failed to parse google.com", err)
	}
}

func TestParseMalformed(t *testing.T) {
	_, err := parseRule(0, "")
	if err == nil {
		t.Fatal("should fail to parse empty")
	}

	_, err = parseRule(0, "a")
	if err == nil {
		t.Fatal("should fail to parse invalid ipv4 address")
	}

	_, err = parseRule(0, "1.1.1.1 400")
	if err == nil {
		t.Fatal("should fail to parse port without service")
	}

	_, err = parseRule(0, "1.1.1.1 400-100/tcp")
	if err == nil {
		t.Fatal("should fail to lower port greater than upper port")
	}

	_, err = parseRule(0, "1.1.1.1 a-2/tcp")
	if err == nil {
		t.Fatal("should fail to parse non-numeric upper and lower bounds ports")
	}

	_, err = parseRule(0, "1.1.1.1 1-b/tcp")
	if err == nil {
		t.Fatal("should fail to parse non-numeric upper and lower bounds ports")
	}

	_, err = parseRule(0, "1.1.1.1 122/igmp")
	if err == nil {
		t.Fatal("should fail with unknown service type")
	}

	if err := ValidateRules([]string{
		"1.1.1.1",
		"4.4.4.4",
		"a",
		"1.1.1.1/23 43/tcp a",
	}, []string{}, nil); err == nil {
		t.Fatal("validate should fail if any rule is invalid")

	}

}

func TestParseRules(t *testing.T) {
	/*
	   "*": {
	       "Allow": [
	           "7.7.7.7",
	           "google.com"
	       ]
	   },
	   "tester": {
	       "Mfa": [
	           "192.168.3.0/24",
	           "192.168.5.0/24"
	       ],
	       "Allow": [
	           "4.3.3.3/32"
	       ]
	   },
	*/

	publicRules := []string{"7.7.7.7", "google.com"}
	mfaRules := []string{"192.168.3.0/24", "192.168.5.0/24"}

	result, err := ParseRules([]string{}, publicRules, []string{})
	if err != nil {
		t.Fatal(err)
	}

	if len(result) < 2 {
		t.Fatal("resulting number of rules was wrong")
	}

	result, err = ParseRules(mfaRules, publicRules, []string{})
	if err != nil {
		t.Fatal(err)
	}

	if len(result) < 4 {
		t.Fatal("resulting number of rules was wrong")
	}

}

func TestParseRulesDuplicates(t *testing.T) {
	/*
	   "*": {
	       "Allow": [
	           "7.7.7.7",
	           "google.com"
	       ]
	   },
	   "tester": {
	       "Mfa": [
	           "192.168.3.0/24",
	           "192.168.5.0/24"
	       ],
	       "Allow": [
	           "4.3.3.3/32"
	       ]
	   },
	*/

	mfaRules := []string{"192.168.33.1/32", "192.168.33.1/32"}

	result, err := ParseRules(mfaRules, []string{}, []string{})
	if err != nil {
		t.Fatal(err)
	}

	if len(result) < 1 {
		t.Fatal("resulting number of rules was wrong")
	}

}
