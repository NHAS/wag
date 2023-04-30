package router

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/routetypes"

	"github.com/cilium/ebpf"
	"golang.org/x/net/ipv4"
)

const (
	XDP_DROP = 1
	XDP_PASS = 2
)

func TestBasicLoad(t *testing.T) {
	if err := setup("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()
}

func TestBlankPacket(t *testing.T) {

	if err := setup("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	buff := make([]byte, 15)
	value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(buff)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if result(value) != "XDP_DROP" {
		t.Fatal("program did not drop a completely blank packet: did", result(value))
	}
}

func TestAddNewDevices(t *testing.T) {

	if err := setup("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	var ipBytes []byte
	var deviceBytes = make([]byte, 40)

	found := map[string]bool{}

	iter := xdpObjects.Devices.Iterate()
	for iter.Next(&ipBytes, &deviceBytes) {
		ip := net.IP(ipBytes)

		var newDevice fwentry
		err := newDevice.Unpack(deviceBytes)
		if err != nil {
			t.Fatal("unpacking new device:", err)
		}

		if newDevice.lastPacketTime != 0 || newDevice.sessionExpiry != 0 {
			t.Fatal("timers were not 0 immediately after device add")
		}
		found[ip.String()] = true
	}

	if iter.Err() != nil {
		t.Fatalf("iterator reported an error: %s", iter.Err())
	}

	if len(found) != len(out) {
		t.Fatalf("expected number of devices not found when iterating timestamp map %d != %d", len(found), len(out))
	}

	for _, device := range out {
		if !found[device.Address] {
			t.Fatalf("%s not found even though it should have been added", device.Address)
		}
	}

}

func TestAddUser(t *testing.T) {

	if err := setup("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	for _, device := range out {
		policiesTable, err := checkLPMMap(device.Username, xdpObjects.PoliciesTable)
		if err != nil {
			t.Fatal("checking publictable:", err)
		}

		acl := config.GetEffectiveAcl(device.Username)

		results, err := routetypes.ParseRules(routetypes.PUBLIC, acl.Allow)
		if err != nil {
			t.Fatal("parsing rules failed?:", err)
		}

		var allow []string
		for _, r := range results {

			for _, k := range r.Keys {
				allow = append(allow, k.String())
			}
		}

		results, err = routetypes.ParseRules(0, acl.Mfa)
		if err != nil {
			t.Fatal("parsing rules failed?:", err)
		}

		var mfa []string
		for _, r := range results {

			for _, k := range r.Keys {
				mfa = append(mfa, k.String())
			}
		}

		if !contains(policiesTable, allow) {
			t.Fatal("public allow list does not match configured acls\n got: ", policiesTable, "\nexpected:", allow)
		}

		if !contains(policiesTable, mfa) {
			t.Fatal("mfa allow list does not match configured acls\n got: ", policiesTable, "\nexpected:", mfa)
		}

	}
}

func contains(x, y []string) bool {
	f := map[string]bool{}
	for _, nx := range x {
		f[nx] = true
	}

	for _, ny := range y {
		if ok := f[ny]; !ok {
			return false
		}
	}

	return true
}

func TestRoutePriority(t *testing.T) {

	if err := setup("../config/test_roaming_all_routes_mfa_priority.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	headers := []ipv4.Header{

		{
			Version: 4,
			Dst:     net.ParseIP("8.8.8.8"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("11.11.11.11"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.1.1"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP(out[0].Address),
			Src:     net.ParseIP("1.1.1.1"),
			Len:     ipv4.HeaderLen,
		}, {
			Version: 4,
			Dst:     net.ParseIP("192.168.1.1"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
	}

	expectedResults := map[string]uint32{
		headers[0].String(): XDP_DROP,
		headers[1].String(): XDP_PASS,
		headers[2].String(): XDP_PASS,
		headers[3].String(): XDP_PASS,
		headers[4].String(): XDP_PASS,
	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if result(value) != result(expectedResults[headers[i].String()]) {
			t.Logf("(%s) program did not %s packet instead did: %s", headers[i].String(), result(expectedResults[headers[i].String()]), result(value))
			t.Fail()
		}
	}

}

func TestBasicAuthorise(t *testing.T) {
	if err := setup("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address, out[0].Username)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	headers := []ipv4.Header{
		{
			Version: 4,
			Dst:     net.ParseIP("11.11.11.11"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("192.168.3.11"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("8.8.8.8"),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("3.21.11.11"),
			Src:     net.ParseIP(out[1].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("7.7.7.7"),
			Src:     net.ParseIP(out[1].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("4.3.3.3"),
			Src:     net.ParseIP(out[1].Address),
			Len:     ipv4.HeaderLen,
		},
	}

	expectedResults := map[string]uint32{
		headers[0].String(): XDP_DROP,
		headers[1].String(): XDP_PASS,
		headers[2].String(): XDP_PASS,
		headers[3].String(): XDP_DROP,
		headers[4].String(): XDP_PASS,
		headers[5].String(): XDP_DROP,
	}

	mfas := config.GetEffectiveAcl(out[0].Username).Mfa
	for i := range mfas {

		rule, err := routetypes.ParseRule(0, mfas[i])
		if err != nil {
			t.Fatal("could not parse ip: ", err)
		}

		if len(rule.Keys) != 1 {
			t.Fatal("expected to only have one key")
		}

		newHeader := ipv4.Header{
			Version: 4,
			Dst:     rule.Keys[0].AsIP(),
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		}
		headers = append(headers, newHeader)

		expectedResults[newHeader.String()] = XDP_PASS

	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != expectedResults[headers[i].String()] {
			t.Fatalf("%s program did not %s packet instead did: %s", headers[i].String(), result(expectedResults[headers[i].String()]), result(value))
		}
	}

	err = Deauthenticate(out[0].Address)
	if err != nil {
		t.Fatal(err)
	}

	if IsAuthed(out[0].Address) {
		t.Fatal("after setting user as deauthorized it should be.... deauthorized")
	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		if out[0].Address != headers[i].Src.String() {
			continue
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != XDP_DROP {
			t.Fatalf("after deauthenticating, everything should be XDP_DROP instead %s", result(value))
		}
	}

}

func TestSlidingWindow(t *testing.T) {
	if err := setup("../config/test_disabled_max_lifetime.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address, out[0].Username)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(config.GetEffectiveAcl(out[0].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(out[0].Address),
		Len:     ipv4.HeaderLen,
	}

	log.Println(testAuthorizedPacket.Dst, testAuthorizedPacket.Src)

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var beforeDevice fwentry
	deviceBytes, err := xdpObjects.Devices.LookupBytes(net.ParseIP(out[0].Address).To4())
	if err != nil {
		t.Fatal(err)
	}

	err = beforeDevice.Unpack(deviceBytes)
	if err != nil {
		t.Fatal(err)
	}

	var timeoutFromMap uint64
	err = xdpObjects.InactivityTimeoutMinutes.Lookup(uint32(0), &timeoutFromMap)
	if err != nil {
		t.Fatal(err)
	}

	difference := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if timeoutFromMap != difference {
		t.Fatal("timeout retrieved from ebpf program does not match json")
	}

	value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 2 {
		t.Fatalf("program did not %s packet instead did: %s", result(2), result(value))
	}

	var afterDevice fwentry
	deviceBytes, err = xdpObjects.Devices.LookupBytes(net.ParseIP(out[0].Address).To4())
	if err != nil {
		t.Fatal(err)
	}

	err = afterDevice.Unpack(deviceBytes)
	if err != nil {
		t.Fatal(err)
	}

	if afterDevice.lastPacketTime == beforeDevice.lastPacketTime {
		t.Fatal("sending a packet did not change sliding window timeout")
	}

	if afterDevice.lastPacketTime < beforeDevice.lastPacketTime {
		t.Fatal("the resulting update must be closer in time")
	}

	t.Logf("Now doing timing test for sliding window waiting %d+10seconds", config.Values().SessionInactivityTimeoutMinutes)

	//Check slightly after inactivity timeout to see if the user is now not authenticated
	time.Sleep(time.Duration(config.Values().SessionInactivityTimeoutMinutes)*time.Minute + 10*time.Second)

	value, _, err = xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 1 {
		t.Fatalf("program did not %s packet instead did: %s", result(1), result(value))
	}

	if IsAuthed(out[0].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestDisabledSlidingWindow(t *testing.T) {
	if err := setup("../config/test_disabled_sliding_window.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	var timeoutFromMap uint64
	err = xdpObjects.InactivityTimeoutMinutes.Lookup(uint32(0), &timeoutFromMap)
	if err != nil {
		t.Fatal(err)
	}

	if timeoutFromMap != math.MaxUint64 {
		t.Fatalf("the inactivity timeout was not set to max uint64, was %d (maxuint64 %d)", timeoutFromMap, uint64(math.MaxUint64))
	}

	err = SetAuthorized(out[0].Address, out[0].Username)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(config.GetEffectiveAcl(out[0].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(out[0].Address),
		Len:     ipv4.HeaderLen,
	}

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Now doing timing test for disabled sliding window waiting...")

	elapsed := 0
	for {
		time.Sleep(15 * time.Second)
		elapsed += 15

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value == 1 {
			if elapsed < config.Values().MaxSessionLifetimeMinutes*60 {
				t.Fatal("epbf kernel blocking valid traffic early")
			} else {
				break
			}

		}
	}

}

func TestMaxSessionLifetime(t *testing.T) {
	if err := setup("../config/test_disabled_sliding_window.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address, out[0].Username)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user device as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(config.GetEffectiveAcl(out[0].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(out[0].Address),
		Len:     ipv4.HeaderLen,
	}

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 2 {
		t.Fatalf("program did not %s packet instead did: %s", result(2), result(value))
	}

	t.Logf("Waiting for %d minutes to test max session timeout", config.Values().MaxSessionLifetimeMinutes)

	time.Sleep(time.Minute * time.Duration(config.Values().MaxSessionLifetimeMinutes))

	value, _, err = xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 1 {
		t.Fatalf("program did not %s packet instead did: %s", result(1), result(value))
	}

	if IsAuthed(out[0].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestDisablingMaxLifetime(t *testing.T) {
	if err := setup("../config/test_disabled_max_lifetime.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address, out[0].Username)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	var maxSessionLifeDevice fwentry
	deviceBytes, err := xdpObjects.Devices.LookupBytes(net.ParseIP(out[0].Address).To4())
	if err != nil {
		t.Fatal(err)
	}

	err = maxSessionLifeDevice.Unpack(deviceBytes)
	if err != nil {
		t.Fatal(err)
	}

	if maxSessionLifeDevice.sessionExpiry != math.MaxUint64 {
		t.Fatalf("lifetime was not set to max uint64, was %d (maxuint64 %d)", maxSessionLifeDevice.sessionExpiry, uint64(math.MaxUint64))
	}

	ip, _, err := net.ParseCIDR(config.GetEffectiveAcl(out[0].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(out[0].Address),
		Len:     ipv4.HeaderLen,
	}

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Now doing timing test for disabled sliding window waiting...")

	elapsed := 0
	for {
		time.Sleep(15 * time.Second)
		elapsed += 15

		t.Logf("waiting %d sec...", elapsed)

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value == 1 {
			t.Fatal("should not block traffic")
		}

		if elapsed > 30 {
			break
		}

	}

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
	r := make([]byte, 9) // 1 byte over as we need to fake some data

	//icmp isnt parsed, other than proto and length

	binary.BigEndian.PutUint16(r, p.src)
	binary.BigEndian.PutUint16(r[2:], p.dst)

	return r
}

func createPacket(src, dst net.IP, proto, port int) []byte {
	iphdr := ipv4.Header{
		Version:  4,
		Dst:      dst,
		Src:      src,
		Len:      ipv4.HeaderLen,
		Protocol: proto,
	}

	hdrbytes, _ := iphdr.Marshal()

	pkt := pkthdr{
		src: 3884,
		dst: uint16(port),
	}

	switch proto {
	case routetypes.UDP:
		hdrbytes = append(hdrbytes, pkt.Udp()...)
	case routetypes.TCP:
		hdrbytes = append(hdrbytes, pkt.Tcp()...)

	case routetypes.ICMP:
		hdrbytes = append(hdrbytes, pkt.Icmp()...)

	default:
		hdrbytes = append(hdrbytes, pkt.Any()...)

	}

	return hdrbytes
}

func TestPortRestrictions(t *testing.T) {
	if err := setup("../config/test_port_based_rules.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	/*
		"Allow": [
			"1.1.0.0/16",
			"2.2.2.2",
			"3.3.3.3 33/tcp",
			"4.4.4.4 43/udp",
			"5.5.5.5 55/any",
			"6.6.6.6 100-150/tcp",
			"7.7.7.7 icmp"
		]
	*/

	acl := config.GetEffectiveAcl(out[0].Username)

	rules, err := routetypes.ParseRules(routetypes.PUBLIC, acl.Allow)
	if err != nil {
		t.Fatal(err)
	}

	var packets [][]byte
	expectedResults := []uint32{}

	flip := true
	for _, rule := range rules {

		for _, policy := range rule.Values {
			if policy.Is(routetypes.STOP) {
				break
			}

			// If we've got an any single port rule e.g 55/any, make sure that the proto is something that has ports otherwise the test fails
			successProto := policy.Proto
			if policy.Proto == routetypes.ANY && policy.LowerPort != routetypes.ANY {
				successProto = routetypes.UDP
			}

			// Add matching/passing packet
			packets = append(packets, createPacket(net.ParseIP(out[0].Address), net.IP(rule.Keys[0].IP[:]), int(successProto), int(policy.LowerPort)))
			expectedResults = append(expectedResults, XDP_PASS)

			if policy.Proto == routetypes.ANY && policy.LowerPort == routetypes.ANY && policy.Is(routetypes.SINGLE) {
				continue
			}

			//Add single port/proto mismatch failing packet
			port := int(policy.LowerPort)
			proto := int(policy.Proto)
			if proto == routetypes.ANY {
				port -= 1
			} else if port == routetypes.ANY {
				proto = 88
			} else {

				if flip {
					proto = 22
				} else {
					port -= 1
				}

				flip = !flip
			}

			packets = append(packets, createPacket(net.ParseIP(out[0].Address), net.IP(rule.Keys[0].IP[:]), proto, port))
			expectedResults = append(expectedResults, XDP_DROP)

			var bogusDstIp net.IP = net.ParseIP("1.1.1.1").To4()

			binary.LittleEndian.PutUint32(bogusDstIp, rand.Uint32())

			if net.IP.Equal(bogusDstIp, net.IP(rule.Keys[0].IP[:])) {
				continue
			}

			// Route miss packet
			packets = append(packets, createPacket(net.ParseIP(out[0].Address), bogusDstIp, int(policy.Proto), int(policy.LowerPort)))
			expectedResults = append(expectedResults, XDP_DROP)

		}
	}

	for i := range packets {

		packet := packets[i]

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != expectedResults[i] {

			var iphdr ipv4.Header
			err := iphdr.Parse(packet)
			if err != nil {
				t.Fatal("packet didnt parse as an IP header: ", err)
			}

			packet = packet[20:]

			var pkt pkthdr
			pkt.pktType = "unknown"

			switch iphdr.Protocol {
			case routetypes.UDP:
				pkt.UnpackUdp(packet)
			case routetypes.TCP:
				pkt.UnpackTcp(packet)
			case routetypes.ICMP:
				pkt.UnpackIcmp(packet)
			case routetypes.ANY:
				pkt.UnpackAny(packet)

			}

			info := iphdr.Src.String() + " -> " + iphdr.Dst.String() + ", proto " + pkt.String()

			t.Fatalf("%s program did not %s packet instead did: %s", info, result(expectedResults[i]), result(value))
		}
	}

}

func TestLookupDifferentKeyTypesInMap(t *testing.T) {
	if err := setup("../config/test_port_based_rules.json"); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	userPublicRoutes, err := getInnerMap(out[0].Username, xdpObjects.PoliciesTable)
	if err != nil {
		t.Fatal(err)
	}

	// Check negative case
	err = userPublicRoutes.Lookup([]byte("3470239uy4skljhd"), nil)
	if err == nil {
		t.Fatal("searched garbage string, should not match")
	}

	/*
	   "Allow": [
	       "1.1.0.0/16",
	       "2.2.2.2",
	       "3.3.3.3 33/tcp",
	       "4.4.4.4 43/udp",
	       "5.5.5.5 55/any",
	       "6.6.6.6 100-150/tcp"
	   ]
	*/

	k := routetypes.Key{
		IP:        [4]byte{1, 1, 1, 1},
		Prefixlen: 32,
	}

	var policies [routetypes.MAX_POLICIES]routetypes.Policy
	err = userPublicRoutes.Lookup(k.Bytes(), &policies)
	if err != nil {
		t.Fatal("searched for valid subnet")
	}

	if !policies[0].Is(routetypes.SINGLE) {
		t.Fatal("the route type was not single: ", policies[0])
	}

	if policies[0].LowerPort != 0 || policies[0].Proto != 0 {
		t.Fatal("policy was not marked as allow all despite having no rules defined")
	}

	if !policies[1].Is(routetypes.STOP) {
		t.Fatal("policy should only contain one any/any rule")
	}

	k = routetypes.Key{
		IP:        [4]byte{3, 3, 3, 3},
		Prefixlen: 32,
	}

	err = userPublicRoutes.Lookup(k.Bytes(), &policies)
	if err != nil {
		t.Fatal("searched for ip failed")
	}

	if !policies[0].Is(routetypes.SINGLE) {
		t.Fatal("the route type was not single")
	}

	if policies[0].LowerPort != 33 || policies[0].Proto != routetypes.TCP {
		t.Fatal("policy had incorrect proto and port defintions")
	}

	if !policies[1].Is(routetypes.STOP) {
		t.Fatal("policy should only contain one any/any rule")
	}

}

func getInnerMap(username string, m *ebpf.Map) (*ebpf.Map, error) {
	var innerMapID ebpf.MapID
	userid := sha1.Sum([]byte(username))

	err := m.Lookup(userid, &innerMapID)
	if err != nil {
		return nil, err
	}

	innerMap, err := ebpf.NewMapFromID(innerMapID)
	if err != nil {
		return nil, fmt.Errorf("failed to get map from id: %s", err)
	}

	return innerMap, nil
}

func checkLPMMap(username string, m *ebpf.Map) ([]string, error) {

	innerMap, err := getInnerMap(username, m)
	if err != nil {
		return nil, err
	}

	result := []string{}

	var innerKey []byte
	var val uint8
	innerIter := innerMap.Iterate()
	kv := routetypes.Key{}
	for innerIter.Next(&innerKey, &val) {
		kv.Unpack(innerKey)

		result = append(result, kv.String())
	}

	if innerIter.Err() != nil {
		return nil, innerIter.Err()
	}

	return result, innerMap.Close()
}

func result(code uint32) string {
	switch code {
	case XDP_DROP:
		return "XDP_DROP"
	case XDP_PASS:
		return "XDP_PASS"
	default:
		return fmt.Sprintf("XDP_UNKNOWN_UNUSED(%d)", code)
	}
}

func addDevices() ([]data.Device, error) {

	devices := []data.Device{
		{
			Address:   "192.168.1.2",
			Publickey: "dc99y+fmhaHwFToSIw/1MSVXewbiyegBMwNGA6LG8yM=",
			Username:  "tester",
			Attempts:  0,
		},
		{
			Address:   "192.168.1.3",
			Publickey: "sXns6f8d6SMehnT6DQG8URCXnNCFe6ouxVmpJB7WeS0=",
			Username:  "randomthingappliedtoall",
			Attempts:  0,
		},
	}

	for i := range devices {
		err := AddUser(devices[i].Username, config.GetEffectiveAcl(devices[i].Username))
		if err != nil {
			return nil, err
		}

		err = xdpAddDevice(devices[i].Username, devices[i].Address)
		if err != nil {
			return nil, err
		}
	}
	return devices, nil
}

func setup(what string) error {
	err := config.Load(what)
	if err != nil && !strings.Contains(err.Error(), "Configuration has already been loaded") {
		return err
	}

	err = data.Load(config.Values().DatabaseLocation)
	if err != nil {
		return err
	}

	return loadXDP()
}
