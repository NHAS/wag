package routetypes

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ANY = uint16(iota)
	RANGE
	SINGLE
)

/*
// Inner map is a LPM tri, so we use this as the key
struct ip4_trie_key

	{
	    __u32 prefixlen; // first member must be u32

	    __u16 rule_type; // rest can be arbitrary

	    __u16 proto;
	    __u16 port;

		__u16 PAD1;

		__u32 addr;
	};
*/
type Key struct {

	// first member must be a prefix u32 wide
	// rest can are arbitrary
	Prefixlen uint32 //4

	RuleType uint16 //2

	// Both of these are big endian
	Protocol uint16 //2,
	Port     uint16 //2

	IP net.IP // 4
}

func (l Key) Bytes() []byte {
	output := make([]byte, 16)
	binary.LittleEndian.PutUint32(output, l.Prefixlen)

	binary.LittleEndian.PutUint16(output[4:], l.RuleType)

	binary.BigEndian.PutUint16(output[6:], l.Protocol)
	binary.BigEndian.PutUint16(output[8:], l.Port)

	// Padding goes here

	copy(output[12:], l.IP.To4())

	return output
}

func (l *Key) Unpack(b []byte) error {
	if len(b) < 16 {
		return errors.New("too short")
	}

	l.Prefixlen = binary.LittleEndian.Uint32(b)
	l.RuleType = binary.LittleEndian.Uint16(b[4:])

	l.Protocol = binary.BigEndian.Uint16(b[6:])
	l.Port = binary.BigEndian.Uint16(b[8:])
	//Ignore padding
	l.IP = b[12:16]

	return nil
}

func (l Key) String() string {

	var serviceInfo string
	if l.RuleType == SINGLE {
		serviceInfo = fmt.Sprintf(" %d/%s", l.Port, lookupProtocol(l.Protocol))
	}
	return fmt.Sprintf("%s/%d %s", l.IP.String(), l.Prefixlen-64, lookupRuleType(l.RuleType)) + serviceInfo
}

func lookupRuleType(t uint16) string {
	switch t {
	case ANY:
		return "any"
	case RANGE:
		return "range"
	case SINGLE:
		return "single"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func lookupProtocol(t uint16) string {
	switch t {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case ICMP:
		return "icmp"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
