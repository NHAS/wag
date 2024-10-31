package routetypes

import (
	"fmt"
	"net"
	"net/netip"
)

type Key struct {

	// first member must be a prefix u32 wide
	// rest can be arbitrary
	Prefixlen uint32
	IP        []byte
}

func (l *Key) ToPrefix() netip.Prefix {

	addr, _ := netip.AddrFromSlice(l.IP)

	return netip.PrefixFrom(addr, int(l.Prefixlen))
}

func (l *Key) AsIPv4() net.IP {
	return net.IP(l.IP).To4()
}

func (l *Key) AsIPv6() net.IP {
	return net.IP(l.IP).To16()
}

func (l Key) String() string {
	return fmt.Sprintf("%s/%d", net.IP(l.IP).String(), l.Prefixlen)
}

func lookupProtocol(t uint16) string {
	switch t {
	case ANY:
		return "any"
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
