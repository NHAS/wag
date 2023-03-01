package routetypes

import (
	"net"
	"testing"
)

func TestAnyMarshalAndUnmarshal(t *testing.T) {

	a := Any{
		Proto: 4444,
		Port:  2222,
	}

	b := a.Bytes()
	if len(b)%8 != 0 {
		t.Fatal("the length of the marshalled bytes is not divisible by 8: ", len(b))
	}

	var c Any
	if err := c.Unpack(b); err != nil {
		t.Fatal(err)
	}

	if c.Port != a.Port {
		t.Fatal("the unpacked port number was incorrect: expected: ", a.Port, " got: ", c.Port)
	}

	if c.Proto != a.Proto {
		t.Fatal("the unpacked protocol number was incorrect: expected: ", a.Proto, " got: ", c.Proto)
	}

}

func TestRangeMarshalAndUnmarshal(t *testing.T) {

	a := Range{
		Proto:     4444,
		LowerPort: 2222,
		UpperPort: 6666,
	}

	b := a.Bytes()
	if len(b)%8 != 0 {
		t.Fatal("the length of the marshalled bytes is not divisible by 8: ", len(b))
	}

	var c Range
	if err := c.Unpack(b); err != nil {
		t.Fatal(err)
	}

	if c.LowerPort != a.LowerPort {
		t.Fatal("the unpacked lower port number was incorrect: expected: ", a.LowerPort, " got: ", c.LowerPort)
	}

	if c.UpperPort != a.UpperPort {
		t.Fatal("the unpacked upper port number was incorrect: expected: ", a.UpperPort, " got: ", c.UpperPort)
	}

	if c.Proto != a.Proto {
		t.Fatal("the unpacked protocol number was incorrect: expected: ", a.Proto, " got: ", c.Proto)
	}

}

func TestKeyMarshalAndUnmarshal(t *testing.T) {

	a := Key{
		Prefixlen: 16,
		RuleType:  RANGE,
		Protocol:  4444,
		Port:      2222,
		IP:        net.IPv4(11, 11, 11, 11),
	}

	b := a.Bytes()
	if len(b)%8 != 0 {
		t.Fatal("the length of the marshalled bytes is not divisible by 8: ", len(b))
	}

	var c Key
	if err := c.Unpack(b); err != nil {
		t.Fatal(err)
	}

	if c.Prefixlen != a.Prefixlen {
		t.Fatal("the unpacked Prefixlen was incorrect: expected: ", a.Prefixlen, " got: ", c.Prefixlen)
	}

	if c.RuleType != a.RuleType {
		t.Fatal("the unpacked RuleType was incorrect: expected: ", a.RuleType, " got: ", c.RuleType)
	}

	if c.Protocol != a.Protocol {
		t.Fatal("the unpacked protocol number was incorrect: expected: ", a.Protocol, " got: ", c.Protocol)
	}

	if c.Port != a.Port {
		t.Fatal("the unpacked port number was incorrect: expected: ", a.Port, " got: ", c.Port)
	}
	if !net.IP.Equal(a.IP.To4(), c.IP.To4()) {
		t.Fatal("the ip address did not unmarshal correctly: expected: ", a.IP, []byte(a.IP.To4()), " got: ", c.IP, []byte(c.IP.To4()))
	}

}
