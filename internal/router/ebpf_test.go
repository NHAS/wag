package router

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/routetypes"

	"github.com/cilium/ebpf"
	"golang.org/x/net/ipv4"
)

var devices = map[string]data.Device{
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

func TestBlankPacket(t *testing.T) {

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

	var ipBytes []byte
	var deviceBytes = make([]byte, 48)

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
		policiesTable, err := checkLPMMap(device.Username, xdpObjects.PoliciesTable)
		if err != nil {
			t.Fatal("checking policy table:", err)
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

		if !contains(policiesTable, resultsAsString) {
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

	err := SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(devices["tester"].Address) {
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

	expectedResults := map[string]uint32{
		// Tester
		headers[0].String(): XDP_DROP,
		headers[1].String(): XDP_PASS,
		headers[2].String(): XDP_PASS,

		// randomthingappliedtoall
		headers[3].String(): XDP_DROP,
		headers[4].String(): XDP_PASS,
		headers[5].String(): XDP_DROP,
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
			Dst:     mfas[i].Keys[0].AsIP(),
			Src:     net.ParseIP(devices["tester"].Address),
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

	err = Deauthenticate(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	if IsAuthed(devices["tester"].Address) {
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

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != XDP_DROP {
			t.Fatalf("after deauthenticating, should be XDP_DROP: %s", headers[i].String())
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

	expectedResults := map[string]uint32{
		headers[0].String(): XDP_DROP,
		headers[1].String(): XDP_PASS,
		headers[2].String(): XDP_PASS,
		headers[3].String(): XDP_DROP,
		headers[4].String(): XDP_PASS,
		headers[5].String(): XDP_DROP,
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
			t.Logf("%s program did not %s packet instead did: %s", headers[i].String(), result(expectedResults[headers[i].String()]), result(value))
			t.Fail()
		}
	}
}

func TestSlidingWindow(t *testing.T) {

	err := SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	ip := net.ParseIP(data.GetEffectiveAcl(devices["tester"].Username).Mfa[0])
	if ip == nil {
		t.Fatal("could not parse ip")
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

	var beforeDevice fwentry
	deviceBytes, err := xdpObjects.Devices.LookupBytes(net.ParseIP(devices["tester"].Address).To4())
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

	difference := uint64(config.Values.SessionInactivityTimeoutMinutes) * 60000000000
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
	deviceBytes, err = xdpObjects.Devices.LookupBytes(net.ParseIP(devices["tester"].Address).To4())
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

	t.Logf("Now doing timing test for sliding window waiting %d+10seconds", config.Values.SessionInactivityTimeoutMinutes)

	//Check slightly after inactivity timeout to see if the user is now not authenticated
	time.Sleep(time.Duration(config.Values.SessionInactivityTimeoutMinutes)*time.Minute + 10*time.Second)

	value, _, err = xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 1 {
		t.Fatalf("program did not %s packet instead did: %s", result(1), result(value))
	}

	if IsAuthed(devices["tester"].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestCompositeRules(t *testing.T) {

	err := SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	successPackets := [][]byte{
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 11),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 8080),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 8080),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 9080),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 50),

		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("7.7.7.7"), routetypes.ICMP, 0),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("7.7.7.7"), routetypes.TCP, 22),
	}

	for i := range successPackets {

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(successPackets[i])
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != XDP_PASS {
			fw, _ := GetRules()
			t.Logf("%+v", fw)
			t.Fatalf("%d program did not XDP_PASS packet instead did: %s", i, result(value))
		}
	}

	err = Deauthenticate(devices["tester"].Address)
	if err != nil {
		t.Fatal(err)
	}

	expectedResults := []uint32{
		XDP_DROP,

		XDP_PASS,
		XDP_PASS,

		XDP_DROP,
		XDP_DROP,

		XDP_PASS,
	}

	packets := [][]byte{

		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 11),

		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 8080),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 8080),

		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.UDP, 9080),
		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.TCP, 50),

		createPacket(net.ParseIP(devices["tester"].Address), net.ParseIP("8.8.8.8"), routetypes.ICMP, 0),
	}

	for i := range packets {

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packets[i])
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != expectedResults[i] {
			//fw, _ := GetRules()
			//t.Logf("%s:%+v", devices["tester"].Username, fw[devices["tester"].Username])
			t.Fatalf("packer no. %d, deauth expect %s did: %s", i, result(expectedResults[i]), result(value))
		}
	}

}

func TestDisabledSlidingWindow(t *testing.T) {

	err := data.SetSessionInactivityTimeoutMinutes(-1)
	if err != nil {
		t.Fatal(err)
	}

	timeout, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		t.Fatal(err)
	}

	err = SetInactivityTimeout(timeout)
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

	err = SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(devices["tester"].Address) {
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
		time.Sleep(15 * time.Second)
		elapsed += 15

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value == 1 {
			if elapsed < config.Values.MaxSessionLifetimeMinutes*60 {
				t.Fatal("epbf kernel blocking valid traffic early")
			} else {
				break
			}

		}
	}

}

func TestMaxSessionLifetime(t *testing.T) {

	err := SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(devices["tester"].Address) {
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

	value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 2 {
		t.Fatalf("program did not %s packet instead did: %s", result(2), result(value))
	}

	t.Logf("Waiting for %d minutes to test max session timeout", config.Values.MaxSessionLifetimeMinutes)

	time.Sleep(time.Minute * time.Duration(config.Values.MaxSessionLifetimeMinutes))

	value, _, err = xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != 1 {
		t.Fatalf("program did not %s packet instead did: %s", result(1), result(value))
	}

	if IsAuthed(devices["tester"].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestDisablingMaxLifetime(t *testing.T) {

	// Disable session max lifetime
	err := data.SetSessionLifetimeMinutes(-1)
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(devices["tester"].Address, devices["tester"].Username, uint64(data.GetServerID()))
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(devices["tester"].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	var maxSessionLifeDevice fwentry
	deviceBytes, err := xdpObjects.Devices.LookupBytes(net.ParseIP(devices["tester"].Address).To4())
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
	t.Log(GetRoutes("tester"))
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
			packets = append(packets, createPacket(net.ParseIP(devices["tester"].Address), net.IP(rule.Keys[0].IP[:]), int(successProto), int(policy.LowerPort)))
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

			packets = append(packets, createPacket(net.ParseIP(devices["tester"].Address), net.IP(rule.Keys[0].IP[:]), proto, port))
			expectedResults = append(expectedResults, XDP_DROP)

			var bogusDstIp net.IP = net.ParseIP("1.1.1.1").To4()

			binary.LittleEndian.PutUint32(bogusDstIp, rand.Uint32())

			if net.IP.Equal(bogusDstIp, net.IP(rule.Keys[0].IP[:])) {
				continue
			}

			// Route miss packet
			packets = append(packets, createPacket(net.ParseIP(devices["tester"].Address), bogusDstIp, int(policy.Proto), int(policy.LowerPort)))
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

			m, _ := GetRules()
			t.Logf("%+v", m)
			t.Fatalf("%s program did not %s packet instead did: %s", info, result(expectedResults[i]), result(value))
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
				if policy.Is(routetypes.STOP) {
					break
				}

				// If we've got an any single port rule e.g 55/any, make sure that the proto is something that has ports otherwise the test fails
				successProto := policy.Proto
				if policy.Proto == routetypes.ANY && policy.LowerPort != routetypes.ANY {
					successProto = routetypes.UDP
				}

				// Add matching/passing packet
				packets = append(packets, createPacket(net.ParseIP(user.Address), net.IP(rule.Keys[0].IP[:]), int(successProto), int(policy.LowerPort)))
			}
		}

	}
	// We check that for both users, that they all pass. This effectively enables us to check that reordered rules are equal
	for i := range packets {

		packet := packets[i]

		value, _, err := xdpObjects.bpfPrograms.XdpWagFirewall.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		var iphdr ipv4.Header
		err = iphdr.Parse(packet)
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

		if value != XDP_PASS {
			t.Fatalf("program did not XDP_PASS packet instead did: %s", result(value))
		}
	}
}

func TestLookupDifferentKeyTypesInMap(t *testing.T) {

	userPublicRoutes, err := getInnerMap(devices["tester"].Username, xdpObjects.PoliciesTable)
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
		t.Fatal("searched for valid subnet: ", err)
	}

	if !policies[0].Is(routetypes.SINGLE) {
		t.Fatal("the Route type was not single: ", policies[0])
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
		t.Fatal("the Route type was not single")
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
	var val [routetypes.MAX_POLICIES]routetypes.Policy
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

func addDevices() error {

	for _, device := range devices {
		_, err := data.CreateUserDataAccount(device.Username)
		if err != nil {
			return err
		}

		err = AddUser(device.Username, data.GetEffectiveAcl(device.Username))
		if err != nil {
			return err
		}

		err = xdpAddDevice(device.Username, device.Address, uint64(data.GetServerID()))
		if err != nil {
			return err
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

	err = loadXDP()
	if err != nil {
		log.Println("failed to load xdp:", err)
		os.Exit(1)
	}

	err = addDevices()
	if err != nil {
		log.Println("unable to add devices: ", err)
		os.Exit(1)
	}

	code := m.Run()

	data.TearDown()

	os.Exit(code)
}
