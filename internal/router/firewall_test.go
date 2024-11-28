package router

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/routetypes"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	devices = map[string]data.Device{
		"tester": {
			Address:   "192.168.1.2",
			Publickey: "dc99y+fmhaHwFToSIw/1MSVXewbiyegBMwNGA6LG8yM=",
			Username:  "tester",
			Attempts:  0,
		},
		"randomthingappliedtoall": {
			Address:   "192.168.1.3",
			Publickey: "sXns6f8d6SMehnT6DQG8URCXnNCFe6ouxVmpJB7WeS0=",
			Username:  "randomthingappliedtoall",
			Attempts:  0,
		},
		"mfa_priority": {
			Address:   "192.168.1.4",
			Publickey: "qH9BGZYxn67YPYvjm4W/pzeAHaIa70tJMkDmStjbG0c=",
			Username:  "mfa_priority",
			Attempts:  0,
		},
		"route_preference": {
			Address:   "192.168.1.5",
			Publickey: "wCUDrTeD42MjiqUm3k7SuA83vsGMJ96gIu2GvMWSokU=",
			Username:  "route_preference",
			Attempts:  0,
		},
	}

	testFw  *Firewall
	mockTun *tuntest.ChannelTUN
)

func TestSetupRealWireguardDevice(t *testing.T) {

	const dummyIPv4Device = "dev-ipv4"
	tdev4, err := tun.CreateTUN(dummyIPv4Device, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer tdev4.Close()

	const dummyIPv6Device = "dev-ipv6"
	tdev6, err := tun.CreateTUN(dummyIPv6Device, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer tdev6.Close()

	err = testFw.bringUpInterface(dummyIPv4Device, "192.168.0.1/24")
	if err != nil {
		t.Fatal(err)
	}

	err = testFw.bringUpInterface(dummyIPv6Device, "2001:db8::1/6")
	if err != nil {
		t.Fatal(err)
	}
}

func TestBlankPacket(t *testing.T) {

	buff := make([]byte, 15)

	if testFw.Test(buff) {
		t.Fatal("program did not drop a completely blank packet")
	}
}

func TestAddNewDevices(t *testing.T) {

	found := map[string]bool{}

	for address, device := range testFw.addressToDevice {

		if !device.lastPacketTime.IsZero() || !device.sessionExpiry.IsZero() {
			t.Fatal("timers were not 0 immediately after device add")
		}
		found[address.String()] = true
	}

	if len(found) != len(devices) {
		t.Fatalf("expected number of devices not found when iterating timestamp map %d != %d", len(found), len(devices))
	}

	for _, device := range devices {
		if !found[device.Address] {
			t.Fatalf("%s not found even though it should have been added", device.Address)
		}
	}

}

func TestAddUser(t *testing.T) {

	for _, device := range devices {

		policiesTable, ok := testFw.userPolicies[device.Username]
		if !ok {
			t.Fatal("checking policy table, didnt exist for user: ", device.Username)
		}

		acl := data.GetEffectiveAcl(device.Username)

		results, errs := routetypes.ParseRules(acl.Mfa, acl.Allow, nil)
		if len(errs) != 0 {
			t.Fatal("parsing rules failed?:", errs)
		}

		resultsAsString := []string{}
		for _, r := range results {
			for m := range r.Keys {
				resultsAsString = append(resultsAsString, r.Keys[m].String())
			}
		}

		policies := []string{}
		policiesTable.policies.All()(func(pfx netip.Prefix, val *[]routetypes.Policy) bool {

			policies = append(policies, pfx.String())

			return true
		})

		if !contains(policies, resultsAsString) {
			t.Fatal("policies list does not match configured acls\n got: ", policiesTable, "\nexpected:", resultsAsString)
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
	// Test to make sure that MFA routes and restrictions take priority over the allow rule.

	headers := []ipv4.Header{

		{
			Version: 4,
			Dst:     net.ParseIP("8.8.8.8"),
			Src:     net.ParseIP(devices["mfa_priority"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("11.11.11.11"),
			Src:     net.ParseIP(devices["mfa_priority"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.1.1"),
			Src:     net.ParseIP(devices["mfa_priority"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP(devices["mfa_priority"].Address),
			Src:     net.ParseIP("1.1.1.1"),
			Len:     ipv4.HeaderLen,
		}, {
			Version: 4,
			Dst:     net.ParseIP("192.168.1.1"),
			Src:     net.ParseIP(devices["mfa_priority"].Address),
			Len:     ipv4.HeaderLen,
		},
	}

	expectedResults := map[string]bool{
		headers[0].String(): false,
		headers[1].String(): true,
		headers[2].String(): true,
		headers[3].String(): true,
		headers[4].String(): true,
	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		if testFw.Test(packet) != expectedResults[headers[i].String()] {
			t.Logf("(%s) program did not %t packet instead did: %t", headers[i].String(), expectedResults[headers[i].String()], testFw.Test(packet))
			t.Fail()
		}
	}

}

func TestBasicAuthorise(t *testing.T) {

	err := testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	headers := []ipv4.Header{
		{
			Version: 4,
			Dst:     net.ParseIP("12.11.11.11"),
			Src:     net.ParseIP(devices["tester"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("192.168.3.11"),
			Src:     net.ParseIP(devices["tester"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("88.88.88.88"),
			Src:     net.ParseIP(devices["tester"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("3.21.11.11"),
			Src:     net.ParseIP(devices["randomthingappliedtoall"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("66.66.66.66"),
			Src:     net.ParseIP(devices["randomthingappliedtoall"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("4.3.3.3"),
			Src:     net.ParseIP(devices["randomthingappliedtoall"].Address),
			Len:     ipv4.HeaderLen,
		},
	}

	expectedResults := map[string]bool{
		// Tester
		headers[0].String(): false,
		headers[1].String(): true,
		headers[2].String(): true,

		// randomthingappliedtoall
		headers[3].String(): false,
		headers[4].String(): true,
		headers[5].String(): false,
	}

	mfas, errs := routetypes.ParseRules(data.GetEffectiveAcl(devices["tester"].Username).Mfa, nil, nil)
	if len(errs) != 0 {
		t.Fatal("failed to parse mfa rules: ", err)
	}

	for i := range mfas {

		if len(mfas[i].Values) != 1 {
			continue
		}

		newHeader := ipv4.Header{
			Version: 4,
			Dst:     mfas[i].Keys[0].AsIPv4(),
			Src:     net.ParseIP(devices["tester"].Address),
			Len:     ipv4.HeaderLen,
		}
		headers = append(headers, newHeader)

		expectedResults[newHeader.String()] = true

	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		if testFw.Test(packet) != expectedResults[headers[i].String()] {
			t.Fatalf("%s program did not %t packet instead did: %t", headers[i].String(), expectedResults[headers[i].String()], testFw.Test(packet))
		}
	}

	err = testFw.Deauthenticate(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	if testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as deauthorized it should be.... deauthorized")
	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		if devices["tester"].Address != headers[i].Src.String() {
			continue
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		if testFw.Test(packet) != false {
			t.Fatalf("after deauthenticating, should be false: %s", headers[i].String())
		}
	}

}

func TestRoutePreference(t *testing.T) {

	// Check to make sure the most specific route takes preference

	headers := []ipv4.Header{
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.3.43"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.1.11"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.4.1"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("3.21.11.11"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.2.7"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
		{
			Version: 4,
			Dst:     net.ParseIP("1.1.2.3"),
			Src:     net.ParseIP(devices["route_preference"].Address),
			Len:     ipv4.HeaderLen,
		},
	}

	expectedResults := map[string]bool{
		headers[0].String(): false,
		headers[1].String(): true,
		headers[2].String(): true,
		headers[3].String(): false,
		headers[4].String(): true,
		headers[5].String(): false,
	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		if testFw.Test(packet) != expectedResults[headers[i].String()] {
			t.Logf("%s program did not %t packet instead did: %t", headers[i].String(), expectedResults[headers[i].String()], testFw.Test(packet))
			t.Fail()
		}
	}
}

func TestSlidingWindow(t *testing.T) {

	err := testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(data.GetEffectiveAcl(devices["tester"].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(devices["tester"].Address),
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

	testerIp, err := netip.ParseAddr(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	testerDevice, ok := testFw.addressToDevice[testerIp]
	if !ok {
		t.Fatal("could not get tester device using ip")
	}

	var (
		beforeLastPacketTime = testerDevice.lastPacketTime
	)

	difference := uint64(config.Values.Webserver.Tunnel.SessionInactivityTimeoutMinutes) * 60000000000
	if testFw.inactivityTimeout != time.Duration(difference) {
		t.Fatal("timeout retrieved from ebpf program does not match json")
	}

	if !testFw.Test(packet) {
		t.Fatalf("program did not pass packet instead dropped it")
	}

	testerDevice, ok = testFw.addressToDevice[testerIp]
	if !ok {
		t.Fatal("could not get tester device using ip (after testing packet?)")
	}

	if testerDevice.lastPacketTime.Equal(beforeLastPacketTime) {
		t.Fatal("sending a packet did not change sliding window timeout")
	}

	if testerDevice.lastPacketTime.Before(beforeLastPacketTime) {
		t.Fatal("the resulting update must be closer in time")
	}

	t.Logf("Now doing timing test for sliding window waiting %d+10seconds", config.Values.Webserver.Tunnel.SessionInactivityTimeoutMinutes)

	//Check slightly after inactivity timeout to see if the user is now not authenticated
	time.Sleep(time.Duration(config.Values.Webserver.Tunnel.SessionInactivityTimeoutMinutes)*time.Minute + 10*time.Second)

	if testFw.Test(packet) {
		t.Fatalf("program did not drop packet instead passed it")
	}

	if testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestCompositeRules(t *testing.T) {

	err := testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	successPackets := [][]byte{
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 11),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 8080),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 8080),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 9080),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 50),

		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("7.7.7.7"), routetypes.ICMP, 0),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("7.7.7.7"), routetypes.TCP, 22),
	}

	for i := range successPackets {

		if !testFw.Test(successPackets[i]) {
			fw, err := testFw.GetRules()
			if err != nil {
				t.Logf("failed to read fw rules: %s", err)
			}

			s, _ := json.MarshalIndent(fw, "", "\t")

			t.Logf("%s", s)
			t.Fatalf("did not pass packet %d", i)
		}
	}

	err = testFw.Deauthenticate(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := []bool{
		false,

		true,
		true,

		false,
		false,

		true,
	}

	packets := [][]byte{

		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 11),

		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 8080),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 8080),

		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 9080),
		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 50),

		createPacketTests(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.ICMP, 0),
	}

	for i := range packets {

		if testFw.Test(packets[i]) != expectedResults[i] {
			//fw, _ := GetRules()
			//t.Logf("%s:%+v", devices["tester"].Username, fw[devices["tester"].Username])
			t.Fatalf("packer no. %d, expected %t did: %t", i, expectedResults[i], testFw.Test(packets[i]))
		}
	}

}

func TestDisabledSlidingWindow(t *testing.T) {

	err := data.SetSessionInactivityTimeoutMinutes(-1)
	if err != nil {
		t.Fatal(err)
	}

	// no op to give etcd time to update the value
	data.GetSessionInactivityTimeoutMinutes()

	maxSessionLife, _ := data.GetSessionLifetimeMinutes()

	if testFw.inactivityTimeout != -1 {
		t.Fatalf("the inactivity timeout was not set to -1, was %d", testFw.inactivityTimeout)
	}

	err = testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(data.GetEffectiveAcl(devices["tester"].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(devices["tester"].Address),
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

		value := testFw.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if !value {
			if elapsed < maxSessionLife*60 {
				t.Fatal("blocking valid traffic early: ", elapsed)
			} else {
				break
			}

		}

		time.Sleep(15 * time.Second)
		elapsed += 15

	}

}

func TestMaxSessionLifetime(t *testing.T) {

	err := testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user device as authorized it should be.... authorized")
	}

	ip, _, err := net.ParseCIDR(data.GetEffectiveAcl(devices["tester"].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(devices["tester"].Address),
		Len:     ipv4.HeaderLen,
	}

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.Test(packet) {
		t.Fatalf("program did not pass packet instead dropped it")
	}

	t.Logf("Waiting for %d minutes to test max session timeout", config.Values.Webserver.Tunnel.MaxSessionLifetimeMinutes)

	time.Sleep(time.Minute * time.Duration(config.Values.Webserver.Tunnel.MaxSessionLifetimeMinutes))

	if testFw.Test(packet) {
		t.Fatalf("program did not drop packet instead passed it")
	}

	if testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestDisablingMaxLifetime(t *testing.T) {

	// Disable session max lifetime
	err := data.SetSessionLifetimeMinutes(-1)
	if err != nil {
		t.Fatal(err)
	}

	err = testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())
	if err != nil {
		t.Fatal(err)
	}

	if !testFw.IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	addr, err := netip.ParseAddr(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	device := testFw.addressToDevice[addr]

	if !device.disableSessionExpiry {
		t.Fatalf("session expiry not disabled")
	}

	ip, _, err := net.ParseCIDR(data.GetEffectiveAcl(devices["tester"].Username).Mfa[0])
	if err != nil {
		t.Fatal("could not parse ip: ", err)
	}

	testAuthorizedPacket := ipv4.Header{
		Version: 4,
		Dst:     ip,
		Src:     net.ParseIP(devices["tester"].Address),
		Len:     ipv4.HeaderLen,
	}

	if testAuthorizedPacket.Src == nil || testAuthorizedPacket.Dst == nil {
		t.Fatal("could not parse ip")
	}

	packet, err := testAuthorizedPacket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(testFw.GetRoutes("tester"))
	t.Logf("Now doing timing test for disabled sliding window waiting...")

	elapsed := 0
	for {
		time.Sleep(15 * time.Second)
		elapsed += 15

		t.Logf("waiting %d sec...", elapsed)

		value := testFw.Test(packet)

		if !value {
			t.Fatalf("should not block traffic")
		}

		if elapsed > 30 {
			break
		}

	}

}

func TestPortRestrictions(t *testing.T) {

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

	acl := data.GetEffectiveAcl(devices["tester"].Username)

	rules, errs := routetypes.ParseRules(acl.Mfa, acl.Allow, nil)
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	testFw.SetAuthorized(devices["tester"].Address, data.GetServerID())

	var packets [][]byte
	expectedResults := []bool{}

	flip := true
	for _, rule := range rules {

		for _, policy := range rule.Values {

			// If we've got an any single port rule e.g 55/any, make sure that the proto is something that has ports otherwise the test fails
			successProto := policy.Proto
			if policy.Proto == routetypes.ANY && policy.LowerPort != routetypes.ANY {
				successProto = routetypes.UDP
			}

			// Add matching/passing packet
			packets = append(packets, createPacketTests(net.ParseIP(devices["tester"].Address), rule.Keys[0].AsIPv4(), int(successProto), int(policy.LowerPort)))
			expectedResults = append(expectedResults, true)

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

			packets = append(packets, createPacketTests(net.ParseIP(devices["tester"].Address), net.IP(rule.Keys[0].IP[:]), proto, port))
			expectedResults = append(expectedResults, false)

			var bogusDstIp net.IP = net.ParseIP("1.1.1.1").To4()

			binary.LittleEndian.PutUint32(bogusDstIp, rand.Uint32())

			if net.IP.Equal(bogusDstIp, net.IP(rule.Keys[0].IP[:])) {
				continue
			}

			// Route miss packet
			packets = append(packets, createPacketTests(net.ParseIP(devices["tester"].Address), bogusDstIp, int(policy.Proto), int(policy.LowerPort)))
			expectedResults = append(expectedResults, false)

		}
	}

	for i := range packets {

		packet := packets[i]

		decision := testFw.Test(packet)

		if decision != expectedResults[i] {

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

			//m, _ := testFw.GetRules()
			//t.Logf("%+v", m)
			t.Fatalf("%s program did not %t packet instead did: %t", info, expectedResults[i], decision)
		}
	}

}

func TestAgnosticRuleOrdering(t *testing.T) {

	var packets [][]byte

	for _, user := range devices {
		acl := data.GetEffectiveAcl(user.Username)
		rules, err := routetypes.ParseRules(nil, acl.Allow, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Populate expected
		for _, rule := range rules {

			for _, policy := range rule.Values {

				// If we've got an any single port rule e.g 55/any, make sure that the proto is something that has ports otherwise the test fails
				successProto := policy.Proto
				if policy.Proto == routetypes.ANY && policy.LowerPort != routetypes.ANY {
					successProto = routetypes.UDP
				}

				// Add matching/passing packet
				packets = append(packets, createPacketTests(net.ParseIP(user.Address), net.IP(rule.Keys[0].IP[:]), int(successProto), int(policy.LowerPort)))
			}
		}

	}
	// We check that for both users, that they all pass. This effectively enables us to check that reordered rules are equal
	for i := range packets {

		packet := packets[i]

		value := testFw.Test(packet)

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
		t.Log(iphdr.Src.String(), " -> ", iphdr.Dst.String(), ", proto "+pkt.String())

		if !value {
			t.Fatalf("program did not pass packet instead dropped it")
		}
	}
}

func TestLookupDifferentKeyTypesInMap(t *testing.T) {

	userPolicies, ok := testFw.userPolicies[devices["tester"].Username]
	if !ok {
		t.Fatal("user did not have policies", devices["tester"].Username)
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
		IP:        []byte{1, 1, 1, 1},
		Prefixlen: 32,
	}

	policiesPtr := userPolicies.Lookup(k.ToPrefix().Addr())
	if policiesPtr == nil {
		t.Fatal("searched for valid subnet, failed, no policies returned")
	}

	policies := *policiesPtr

	if !policies[0].Is(routetypes.SINGLE) {
		t.Fatal("the Route type was not single: ", policies[0])
	}

	if policies[0].LowerPort != 0 || policies[0].Proto != 0 {
		t.Fatal("policy was not marked as allow all despite having no rules defined")
	}

	k = routetypes.Key{
		IP:        []byte{3, 3, 3, 3},
		Prefixlen: 32,
	}

	policiesPtr = userPolicies.Lookup(k.ToPrefix().Addr())
	if policiesPtr == nil {
		t.Fatal("searched for ip failed")
	}

	policies = *policiesPtr

	if !policies[0].Is(routetypes.SINGLE) {
		t.Fatal("the Route type was not single")
	}

	if policies[0].LowerPort != 33 || policies[0].Proto != routetypes.TCP {
		t.Fatal("policy had incorrect proto and port defintions")
	}

}

func BenchmarkFirewallEvaluate(b *testing.B) {

	var packets [][]byte

	for _, user := range devices {
		acl := data.GetEffectiveAcl(user.Username)
		rules, err := routetypes.ParseRules(nil, acl.Allow, nil)
		if err != nil {
			b.Fatal(err)
		}

		// Populate expected
		for _, rule := range rules {

			for _, policy := range rule.Values {

				// If we've got an any single port rule e.g 55/any, make sure that the proto is something that has ports otherwise the test fails
				successProto := policy.Proto
				if policy.Proto == routetypes.ANY && policy.LowerPort != routetypes.ANY {
					successProto = routetypes.UDP
				}

				// Add matching/passing packet
				packets = append(packets, createPacketTests(net.ParseIP(user.Address), net.IP(rule.Keys[0].IP[:]), int(successProto), int(policy.LowerPort)))
			}
		}

	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := range packets {
			if !testFw.Test(packets[i]) {
				b.Fatal("should pass")
			}
		}
	}
}

func addDevices(fw *Firewall) error {

	for _, device := range devices {

		_, err := data.CreateUserDataAccount(device.Username)
		if err != nil {
			return fmt.Errorf("failed to create data account: %s", err)
		}

		k, err := wgtypes.ParseKey(device.Publickey)
		if err != nil {
			return fmt.Errorf("failed to parse key: %s, err %s", device.Publickey, err)
		}
		err = fw.AddPeer(k, device.Username, device.Address, device.PresharedKey, device.AssociatedNode)
		if err != nil {
			return fmt.Errorf("unable to create peer: %s: err: %s", device.Address, err)
		}
	}
	return nil
}

func TestMain(m *testing.M) {

	if err := config.Load("../config/testing_config.json"); err != nil {
		log.Println("failed to load config: ", err)
		os.Exit(1)
	}

	err := data.Load(config.Values.DatabaseLocation, "", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	mockTun = tuntest.NewChannelTUN()

	testFw, err = newDebugFirewall(mockTun.TUN())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	err = addDevices(testFw)
	if err != nil {
		log.Println("unable to add devices: ", err)
		os.Exit(1)
	}

	code := m.Run()

	data.TearDown()

	testFw.Close()

	os.Exit(code)
}
