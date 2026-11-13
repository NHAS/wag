package routetypes

import (
	"fmt"
	"net"
	"testing"
)

func checkKey(reality Key, expectedKey Key) error {

	if !net.IP.Equal(reality.AsIP(), expectedKey.AsIP()) {
		return fmt.Errorf("key had incorrect ip: expected: %s got: %s", expectedKey.AsIP(), reality.AsIP())
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

func TestIPv6Any(t *testing.T) {
	//https://github.com/NHAS/wag/issues/184
	/*
			"Acls": {
		    "Groups": {
		      "group:admin": ["foobar"]
		    },
		    "Policies": {
		      "group:admin": {
		        "Mfa": ["172.69.0.0/16", "172.63.0.0/16"],
		        "Allow": ["0.0.0.0/0", "::/0"]
		      }
		    }
		  }
	*/

	err := ValidateRules([]string{
		"172.69.0.0/16", "172.63.0.0/16",
	}, []string{
		"0.0.0.0/0", "::/0",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
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

	if len(br) != 1 {
		t.Fatal("parsing single ip should result in single rule output", len(br))
	}

	if err := checkKey(br[0].Key, expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br[0].Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	br, err = parseRule(0, "1.1.1.1/32")
	if err != nil {
		t.Fatal("failed to parse 1.1.1.1/32", err)
	}

	if err := checkKey(br[0].Key, expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br[0].Values[0], expectedValue); err != nil {
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

	if len(br) != 1 {
		t.Fatal("parsing single ip rule should result in single rule", len(br))
	}

	if len(br[0].Values) != 4 {
		t.Fatal("expected to define 4 policies got: ", len(br[0].Values))
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

	for _, policy := range br[0].Values {
		if len(policy.Bytes()) != 8 {
			t.Fatal("policy generated was not 8 bytes")
		}
	}

	if err := checkKey(br[0].Key, expectedKey); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(br[0].Values); i++ {
		found := false
		for _, v := range expectedValues {

			if err := checkPolicy(br[0].Values[i], v); err != nil {
				continue
			}

			found = true
			break
		}

		if !found {
			t.Fatal("did not find rule in set: ", br[0].Values[i].PolicyType)
		}

	}

}

func TestParsePortRange(t *testing.T) {
	br, err := parseRule(0, "1.3.1.3 43-100/tcp")
	if err != nil {
		t.Fatal("failed to parse 1.3.1.3", err)
	}

	if len(br) != 1 {
		t.Fatal("expected to define 1 rule for ip got: ", len(br))
	}

	if len(br[0].Values) != 1 {
		t.Fatal("expected to define 1 policies for key got: ", len(br[0].Values))
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

	if err := checkKey(br[0].Key, expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br[0].Values[0], expectedValue); err != nil {
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

	if err := checkKey(br[0].Key, expected); err != nil {
		t.Fatal(err)
	}

	if err := checkPolicy(br[0].Values[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	expectedValue = Policy{
		PolicyType: SINGLE,
		LowerPort:  55,
		Proto:      TCP,
	}

	if err := checkPolicy(br[0].Values[1], expectedValue); err != nil {
		t.Fatal(err)
	}

	expectedValue = Policy{
		PolicyType: SINGLE,
		LowerPort:  66,
		Proto:      UDP,
	}

	if err := checkPolicy(br[0].Values[2], expectedValue); err != nil {
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

// Public rule for ipB leaks onto ipA: an UNauthenticated device reaches ipA:80.
func TestMultiRecordLeak(t *testing.T) {
	const (
		ipA = "10.10.0.1"
		ipB = "10.10.0.2"
	)

	lookupIPFunc = func(_ string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP(ipA),
			net.ParseIP(ipB),
		}, nil
	}

	mfaRules := []string{"dummy.domain.example 443/tcp"}
	publicRule := []string{ipB + " 80/tcp"}

	result, err := ParseRules(mfaRules, publicRule, []string{})
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 2 {
		t.Fatal("domain with 2 ips and one overlapping rule should result in 2 rules", len(result))
	}

	if !net.IP(result[0].Key.IP).Equal(net.ParseIP(ipA)) {
		t.Fatal("unexpected ip address in first place: ", result[0].Key.IP)
	}

	if len(result[0].Values) != 1 {
		t.Fatal("initial rule for ipA has too many rules", len(result[0].Values))
	}

	if result[0].Values[0].Proto != TCP ||
		result[0].Values[0].LowerPort != 443 ||
		result[0].Values[0].Is(PUBLIC) {
		t.Fatalf("ipA has unknown rule inserted: %+v", result[0])
	}

	if len(result[1].Values) != 2 {
		t.Fatal("initial rule for ipA has too few rules", len(result[1].Values))
	}

	if result[1].Values[0].Proto != TCP ||
		result[1].Values[0].LowerPort != 443 ||
		result[1].Values[0].Is(PUBLIC) {
		t.Fatal("1 ipB unknown rule inserted: ", result[1].Values[0])

	}

	if result[1].Values[1].Proto != TCP ||
		result[1].Values[1].LowerPort != 80 ||
		!result[1].Values[1].Is(PUBLIC) {
		t.Fatal("2 ipB unknown rule inserted: ", result[1].Values[1])
	}

}
