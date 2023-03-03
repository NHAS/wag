package routetypes

import (
	"net"
	"testing"
)

func TestPolicyMarshalAndUnmarshal(t *testing.T) {

	a := Policy{
		PolicyType: RANGE,
		Proto:      4444,
		LowerPort:  2222,
		UpperPort:  6666,
	}

	b := a.Bytes()
	if len(b)%8 != 0 {
		t.Fatal("the length of the marshalled bytes is not divisible by 8: ", len(b))
	}

	var c Policy
	if err := c.Unpack(b); err != nil {
		t.Fatal(err)
	}

	if c.PolicyType != a.PolicyType {
		t.Fatal("the unpacked lower policy type number was incorrect: expected: ", a.PolicyType, " got: ", c.PolicyType)
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

	if !net.IP.Equal(a.IP.To4(), c.IP.To4()) {
		t.Fatal("the ip address did not unmarshal correctly: expected: ", a.IP, []byte(a.IP.To4()), " got: ", c.IP, []byte(c.IP.To4()))
	}

}
