package router

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/NHAS/wag/internal/routetypes"
	"golang.org/x/net/ipv4"
)

func CheckRoute(device string, ip net.IP, proto string, port int) (decision string, err error) {

	deviceIP := net.ParseIP(device)

	pro := routetypes.TCP
	switch proto {
	case "udp":
		pro = routetypes.UDP
	case "icmp":
		pro = routetypes.ICMP
		port = 0
	}

	createPacket(deviceIP, ip, pro, port)

	return "unknown", nil

}

func createPacket(src, dst net.IP, proto, port int) []byte {
	iphdr := ipv4.Header{
		Version:  4,
		Dst:      dst,
		Src:      src,
		Len:      ipv4.HeaderLen,
		Protocol: proto,
	}

	if proto == routetypes.ANY {
		iphdr.Protocol = routetypes.TCP
	}

	pkt := pkthdr{
		src: 3884,
		dst: uint16(port),
	}

	var content []byte
	switch proto {
	case routetypes.UDP:
		content = pkt.Udp()
	case routetypes.TCP:
		content = pkt.Tcp()
	case routetypes.ICMP:
		content = pkt.Icmp()
	default:
		content = pkt.Any()
	}

	iphdr.TotalLen = ipv4.HeaderLen + len(content)

	hdrbytes, err := iphdr.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	hdrbytes = append(hdrbytes, content...)

	return hdrbytes
}

type pkthdr struct {
	pktType string

	src uint16
	dst uint16
}

func (p pkthdr) String() string {
	return fmt.Sprintf("%s, src_port %d, dst_port %d", p.pktType, p.src, p.dst)
}

func (p *pkthdr) UnpackTcp(b []byte) {
	p.pktType = "TCP"
	p.src = binary.BigEndian.Uint16(b)
	p.dst = binary.BigEndian.Uint16(b[2:])
}

func (p *pkthdr) Tcp() []byte {
	r := make([]byte, 21) // 1 byte over as we need to fake some data

	binary.BigEndian.PutUint16(r, p.src)
	binary.BigEndian.PutUint16(r[2:], p.dst)

	return r
}

func (p *pkthdr) UnpackUdp(b []byte) {
	p.pktType = "UDP"
	p.src = binary.BigEndian.Uint16(b)
	p.dst = binary.BigEndian.Uint16(b[2:])
}

func (p *pkthdr) Udp() []byte {
	r := make([]byte, 9) // 1 byte over as we need to fake some data

	binary.BigEndian.PutUint16(r, p.src)
	binary.BigEndian.PutUint16(r[2:], p.dst)

	return r
}

func (p *pkthdr) UnpackIcmp(b []byte) {
	p.pktType = "ICMP"
}

func (p *pkthdr) Icmp() []byte {
	r := make([]byte, 9) // 1 byte over as we need to fake some data

	//icmp isnt parsed, other than proto and length

	return r
}

func (p *pkthdr) UnpackAny(b []byte) {
	p.pktType = "Any"
	p.src = binary.BigEndian.Uint16(b)
	p.dst = binary.BigEndian.Uint16(b[2:])
}

func (p *pkthdr) Any() []byte {
	r := make([]byte, 21) // 1 byte over as we need to fake some data

	binary.BigEndian.PutUint16(r, p.src)
	binary.BigEndian.PutUint16(r[2:], p.dst)

	return r
}
