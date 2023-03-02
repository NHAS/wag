package routetypes

import (
	"fmt"
	"log"
	"net"
	"testing"
)

func checkKey(br BinaryRule, expectedKey Key) error {
	var (
		k Key
	)

	if len(expectedKey.Bytes()) != len(br.Key) {
		return fmt.Errorf("expected key size not actual key size: exp %d real %d", len(expectedKey.Bytes()), len(br.Key))
	}
	if err := k.Unpack(br.Key); err != nil {
		return fmt.Errorf("could not unpack key: %s", err)
	}

	if !net.IP.Equal(expectedKey.IP, k.IP) {
		return fmt.Errorf("key had incorrect ip: expected: %s got: %s", expectedKey.IP, k.IP)
	}

	if k.RuleType != expectedKey.RuleType {
		return fmt.Errorf("key had incorrect rule type should be %d, was %d", expectedKey.RuleType, k.RuleType)
	}

	if k.Prefixlen != expectedKey.Prefixlen {
		return fmt.Errorf("key had incorrect prefix length, should be %d, was: %d", expectedKey.Prefixlen, k.Prefixlen)
	}

	return nil
}

func checkAny(br BinaryRule, expectedValue Any) error {
	var a Any

	if err := a.Unpack(br.Value); err != nil {
		return fmt.Errorf("could not unpack value: %s", err)
	}

	if a.Port != expectedValue.Port {
		return fmt.Errorf("value port was not %d, was: %d", expectedValue.Port, a.Port)
	}

	if a.Proto != expectedValue.Proto {
		return fmt.Errorf("value proto was not %d, was: %d", expectedValue.Proto, a.Proto)
	}

	return nil
}

func checkRange(br BinaryRule, expectedValue Range) error {
	var r Range

	if err := r.Unpack(br.Value); err != nil {
		return fmt.Errorf("could not unpack value: %s", err)
	}

	if r.LowerPort != expectedValue.LowerPort {
		return fmt.Errorf("value lower port was not %d, was: %d", expectedValue.LowerPort, r.LowerPort)
	}

	if r.LowerPort != expectedValue.LowerPort {
		return fmt.Errorf("value upper port was not %d, was: %d", expectedValue.UpperPort, r.UpperPort)
	}

	if r.Proto != expectedValue.Proto {
		return fmt.Errorf("value proto was not %d, was: %d", expectedValue.Proto, r.Proto)
	}

	return nil
}

func TestParseEasyRules(t *testing.T) {

	expected := Key{
		IP:        net.IPv4(1, 1, 1, 1),
		RuleType:  ANY,
		Prefixlen: 96,
	}

	expectedValue := Any{
		Proto: ANY,
		Port:  ANY,
	}

	br, err := ParseRule("1.1.1.1")
	if err != nil {
		t.Fatal("failed to parse 1.1.1.1", err)
	}

	if err := checkKey(br[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkAny(br[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	br, err = ParseRule("1.1.1.1/32")
	if err != nil {
		t.Fatal("failed to parse 1.1.1.1/32", err)
	}

	if err := checkKey(br[0], expected); err != nil {
		t.Fatal(err)
	}

	if err := checkAny(br[0], expectedValue); err != nil {
		t.Fatal(err)
	}
}

func TestParseSimpleSingles(t *testing.T) {
	br, err := ParseRule("1.2.1.2 43/tcp 23/udp icmp 55/any")
	if err != nil {
		t.Fatal("failed to parse 1.2.1.2", err)
	}

	if len(br) != 4 {
		log.Fatal("expected to define 4 binary rules only got: ", len(br))
	}

	expected := Key{
		Prefixlen: 96,
		RuleType:  SINGLE,
		Protocol:  TCP,
		Port:      43,
		IP:        net.IPv4(1, 2, 1, 2),
	}

	if err := checkKey(br[0], expected); err != nil {
		t.Fatal(err)
	}

	expected.Protocol = UDP
	expected.Port = 23

	if err := checkKey(br[1], expected); err != nil {
		t.Fatal(err)
	}

	expected.Prefixlen = 96
	expected.RuleType = ANY

	expected.Protocol = 0
	expected.Port = 0

	if err := checkKey(br[2], expected); err != nil {
		t.Fatal(err)
	}

	expectedValue := Any{
		Proto: ICMP,
		Port:  ICMP,
	}

	if err := checkAny(br[2], expectedValue); err != nil {
		t.Fatal(err)
	}

	expected.Prefixlen = 96
	expected.RuleType = ANY

	expected.Protocol = 0
	expected.Port = 0

	if err := checkKey(br[3], expected); err != nil {
		t.Fatal(err)
	}

	expectedValue.Port = 55
	expectedValue.Proto = 0

	if err := checkAny(br[3], expectedValue); err != nil {
		t.Fatal(err)
	}

}

func TestParsePortRange(t *testing.T) {
	br, err := ParseRule("1.3.1.3 43-100/tcp")
	if err != nil {
		t.Fatal("failed to parse 1.3.1.3", err)
	}

	if len(br) != 1 {
		log.Fatal("expected to define 1 binary rules only got: ", len(br))
	}

	expected := Key{
		Prefixlen: 96,
		RuleType:  RANGE,
		IP:        net.IPv4(1, 3, 1, 3),
	}

	expectedValue := Range{
		LowerPort: 43,
		UpperPort: 100,
		Proto:     TCP,
	}

	if err := checkKey(br[0], expected); err != nil {
		t.Fatal(err)
	}

	if checkRange(br[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	br, err = ParseRule("1.4.1.4 43-100/any 55/tcp 66/udp")
	if err != nil {
		t.Fatal("failed to parse 1.4.1.4", err)
	}

	expected = Key{
		Prefixlen: 96,
		RuleType:  RANGE,
		IP:        net.IPv4(1, 4, 1, 4),
	}

	expectedValue = Range{
		LowerPort: 43,
		UpperPort: 100,
		Proto:     ANY,
	}

	if err := checkKey(br[0], expected); err != nil {
		t.Fatal(err)
	}

	if checkRange(br[0], expectedValue); err != nil {
		t.Fatal(err)
	}

	expected = Key{
		Prefixlen: 96,
		RuleType:  SINGLE,
		Port:      55,
		Protocol:  TCP,
		IP:        net.IPv4(1, 4, 1, 4),
	}

	if err := checkKey(br[1], expected); err != nil {
		t.Fatal(err)
	}

	expected = Key{
		Prefixlen: 96,
		RuleType:  SINGLE,
		Port:      66,
		Protocol:  UDP,
		IP:        net.IPv4(1, 4, 1, 4),
	}

	if err := checkKey(br[2], expected); err != nil {
		t.Fatal(err)
	}

}

func TestParseDomainRules(t *testing.T) {
	_, err := ParseRule("google.com 443/tcp")
	if err != nil {
		t.Fatal("failed to parse google.com", err)
	}
}

func TestParseMalformed(t *testing.T) {
	_, err := ParseRule("")
	if err == nil {
		t.Fatal("should fail to parse empty")
	}

	_, err = ParseRule("a")
	if err == nil {
		t.Fatal("should fail to parse invalid ipv4 address")
	}

	_, err = ParseRule("1.1.1.1 400")
	if err == nil {
		t.Fatal("should fail to parse port without service")
	}

	_, err = ParseRule("1.1.1.1 400-100/tcp")
	if err == nil {
		t.Fatal("should fail to lower port greater than upper port")
	}

	_, err = ParseRule("1.1.1.1 a-2/tcp")
	if err == nil {
		t.Fatal("should fail to parse non-numeric upper and lower bounds ports")
	}

	_, err = ParseRule("1.1.1.1 1-b/tcp")
	if err == nil {
		t.Fatal("should fail to parse non-numeric upper and lower bounds ports")
	}

	_, err = ParseRule("1.1.1.1 122/igmp")
	if err == nil {
		t.Fatal("should fail with unknown service type")
	}

	if err := ValidateRules([]string{
		"1.1.1.1",
		"4.4.4.4",
		"a",
		"1.1.1.1/23 43/tcp a",
	}); err == nil {
		t.Fatal("validate should fail if any rule is invalid")

	}

}
