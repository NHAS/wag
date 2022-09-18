package router

import (
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"
	"wag/config"
	"wag/database"

	"github.com/cilium/ebpf"
	"golang.org/x/net/ipv4"
)

func TestBasicLoad(t *testing.T) {
	if err := setup("../example_config.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
}

func TestBlankPacket(t *testing.T) {

	if err := setup("../example_config.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	buff := make([]byte, 15)

	value, _, err := objs.TcIngress.Test(buff)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != TC_ACT_SHOT {
		t.Fatal("program did not drop a completely blank packet: did", result(value))
	}
}

func TestAddNewDevices(t *testing.T) {

	if err := setup("../example_config.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = checkTimestampMap(out, objs.LastPacketTime)
	if err != nil {
		t.Fatal("checking lastpackettime:", err)
	}

	err = checkTimestampMap(out, objs.Sessions)
	if err != nil {
		t.Fatal("checking sessions:", err)
	}

	pubs := []database.Device{}
	for _, device := range out {
		if len(config.GetEffectiveAcl(device.Username).Allow) > 0 {
			pubs = append(pubs, device)
		}
	}

	publicAcls, err := checkLPMMap(pubs, objs.PublicTable)
	if err != nil {
		t.Fatal("checking publictable:", err)
	}

	mfas := []database.Device{}
	for _, device := range out {
		if len(config.GetEffectiveAcl(device.Username).Mfa) > 0 {
			mfas = append(mfas, device)
		}
	}

	mfaAcls, err := checkLPMMap(mfas, objs.MfaTable)
	if err != nil {
		t.Fatal("checking mfatable:", err)
	}

	for _, device := range out {
		acl := config.GetEffectiveAcl(device.Username)
		if !sameStringSlice(acl.Allow, publicAcls[device.Address]) {
			t.Fatal("public allow list does not match configured acls")
		}

		if !sameStringSlice(acl.Mfa, mfaAcls[device.Address]) {
			t.Fatal("mfa allow list does not match configured acls")
		}
	}
}

func TestBasicAuthorise(t *testing.T) {
	if err := setup("../example_config.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address)
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
	}

	expectedResults := map[string]uint32{
		headers[0].String(): TC_ACT_SHOT,
	}

	mfas := config.GetEffectiveAcl(out[0].Username).Mfa
	for i := range mfas {

		ip, _, err := net.ParseCIDR(mfas[i])
		if err != nil {
			t.Fatal("could not parse ip: ", err)
		}

		newHeader := ipv4.Header{
			Version: 4,
			Dst:     ip,
			Src:     net.ParseIP(out[0].Address),
			Len:     ipv4.HeaderLen,
		}
		headers = append(headers, newHeader)

		expectedResults[newHeader.String()] = TC_ACT_OK

	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := objs.TcIngress.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if result(value) != result(expectedResults[headers[i].String()]) {
			t.Fatalf("program did not %s packet instead did: %s", result(expectedResults[headers[i].String()]), result(value))
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

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := objs.TcIngress.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value != TC_ACT_SHOT {
			t.Fatalf("after deauthenticating, everything should be TC_ACT_SHOT instead %s", result(value))
		}
	}

}

func TestSlidingWindow(t *testing.T) {
	if err := setup("../example_config.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address)
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

	var before uint64
	err = objs.LastPacketTime.Lookup(net.ParseIP(out[0].Address).To4(), &before)
	if err != nil {
		t.Fatal(err)
	}

	var timeoutFromMap uint64
	err = objs.InactivityTimeoutMinutes.Lookup(uint32(0), &timeoutFromMap)
	if err != nil {
		t.Fatal(err)
	}

	difference := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if timeoutFromMap != difference {
		t.Fatal("timeout retrieved from ebpf program does not match json")
	}

	value, _, err := objs.TcIngress.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != TC_ACT_OK {
		t.Fatalf("program did not %s packet instead did: %s", result(TC_ACT_OK), result(value))
	}

	var after uint64
	err = objs.LastPacketTime.Lookup(net.ParseIP(out[0].Address).To4(), &after)
	if err != nil {
		t.Fatal(err)
	}

	if after == before {
		t.Fatal("sending a packet did not change sliding window timeout")
	}

	if after < before {
		t.Fatal("the resulting update must be closer in time")
	}

	t.Logf("Now doing timing test for sliding window waiting %d+10seconds", config.Values().SessionInactivityTimeoutMinutes)

	//Check slightly after inactivity timeout to see if the user is now not authenticated
	time.Sleep(time.Duration(config.Values().SessionInactivityTimeoutMinutes)*time.Minute + 10*time.Second)

	value, _, err = objs.TcIngress.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != TC_ACT_SHOT {
		t.Fatalf("program did not %s packet instead did: %s", result(TC_ACT_SHOT), result(value))
	}

	if IsAuthed(out[0].Address) {
		t.Fatal("user is still authorized after inactivity timeout should have killed them")
	}
}

func TestDisabledSlidingWindow(t *testing.T) {
	if err := setup("../config/test_disabled_sliding_window.json"); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	var timeoutFromMap uint64
	err = objs.InactivityTimeoutMinutes.Lookup(uint32(0), &timeoutFromMap)
	if err != nil {
		t.Fatal(err)
	}

	if timeoutFromMap != math.MaxUint64 {
		t.Fatalf("the inactivity timeout was not set to max uint64, was %d (maxuint64 %d)", timeoutFromMap, uint64(math.MaxUint64))
	}

	err = SetAuthorized(out[0].Address)
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

		value, _, err := objs.TcIngress.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value == TC_ACT_SHOT {
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
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address)
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

	value, _, err := objs.TcIngress.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != TC_ACT_OK {
		t.Fatalf("program did not %s packet instead did: %s", result(TC_ACT_OK), result(value))
	}

	t.Logf("Waiting for %d minutes to test max session timeout", config.Values().MaxSessionLifetimeMinutes)

	time.Sleep(time.Minute * time.Duration(config.Values().MaxSessionLifetimeMinutes))

	value, _, err = objs.TcIngress.Test(packet)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if value != TC_ACT_SHOT {
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
	defer objs.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = SetAuthorized(out[0].Address)
	if err != nil {
		t.Fatal(err)
	}

	if !IsAuthed(out[0].Address) {
		t.Fatal("after setting user as authorized it should be.... authorized")
	}

	var maxSessionLife uint64
	err = objs.Sessions.Lookup(net.ParseIP(out[0].Address).To4(), &maxSessionLife)
	if err != nil {
		t.Fatal(err)
	}

	if maxSessionLife != math.MaxUint64 {
		t.Fatalf("lifetime was not set to max uint64, was %d (maxuint64 %d)", maxSessionLife, uint64(math.MaxUint64))
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

		value, _, err := objs.TcIngress.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if value == TC_ACT_SHOT {
			t.Fatal("should not block traffic")
		}

		if elapsed > 30 {
			break
		}

	}

}

// https://stackoverflow.com/questions/36000487/check-for-equality-on-slices-without-order
func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}

	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}

func checkTimestampMap(devices []database.Device, m *ebpf.Map) error {
	var ipBytes []byte
	var time uint64

	found := map[string]bool{}

	iter := m.Iterate()
	for iter.Next(&ipBytes, &time) {
		ip := net.IP(ipBytes)
		if time != 0 {
			return fmt.Errorf("timer was not 0 immediately after device add")
		}
		found[ip.String()] = true
	}

	if iter.Err() != nil {
		return fmt.Errorf("iterator reported an error: %s", iter.Err())
	}

	if len(found) != len(devices) {
		return fmt.Errorf("expected number of devices not found when iterating timestamp map %d != %d", len(found), len(devices))
	}

	for _, device := range devices {
		if !found[device.Address] {
			return fmt.Errorf("%s not found even though it should have been added", device.Address)
		}
	}

	return nil
}

func checkLPMMap(devices []database.Device, m *ebpf.Map) (map[string][]string, error) {
	var innerMapID ebpf.MapID
	var ipBytes []byte

	found := map[string][]string{}

	iter := m.Iterate()
	for iter.Next(&ipBytes, &innerMapID) {
		ip := net.IP(ipBytes)

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("failed to get map from id: %s", err)
		}

		var innerKey []byte
		var val uint8
		innerIter := innerMap.Iterate()
		kv := Key{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)

			found[ip.String()] = append(found[ip.String()], kv.String())
		}
		innerMap.Close()
	}

	if iter.Err() != nil {
		return nil, fmt.Errorf("iterator reported an error: %s", iter.Err())
	}

	if len(found) != len(devices) {
		return nil, fmt.Errorf("expected number of devices not found when iterating lpm map %d != %d", len(found), len(devices))
	}

	for _, device := range devices {
		if _, ok := found[device.Address]; !ok {
			return nil, fmt.Errorf("%s not found even though it should have been added", device.Address)
		}
	}

	return found, nil
}

const (
	TC_ACT_OK   = 0
	TC_ACT_SHOT = 2
)

func result(code uint32) string {
	switch code {
	case 0:
		return "TC_ACT_OK"
	case 2:
		return "TC_ACT_SHOT"
	default:
		return "UNKNOWN_UNUSED"
	}
}

func addDevices() ([]database.Device, error) {

	devices := []database.Device{
		{
			Address:   "192.168.1.2",
			Publickey: "dc99y+fmhaHwFToSIw/1MSVXewbiyegBMwNGA6LG8yM=",
			Username:  "tester",
			Enforcing: true,
			Attempts:  0,
		},
		{
			Address:   "192.168.1.3",
			Publickey: "sXns6f8d6SMehnT6DQG8URCXnNCFe6ouxVmpJB7WeS0=",
			Username:  "randomthingappliedtoall",
			Enforcing: true,
			Attempts:  0,
		},
	}

	for i := range devices {
		err := xdpAddDevice(devices[i])
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

	return loadXDP()
}
