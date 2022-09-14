package router

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"wag/config"
	"wag/database"

	"github.com/cilium/ebpf"
	"golang.org/x/net/ipv4"
)

func TestBasicLoad(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()
}

func TestBlankPacket(t *testing.T) {

	if err := setup(); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	buff := make([]byte, 15)
	value, _, err := xdpObjects.XdpProgFunc.Test(buff)
	if err != nil {
		t.Fatalf("program failed %s", err)
	}

	if result(value) != "XDP_DROP" {
		t.Fatal("program did not drop a completely blank packet: did", result(value))
	}
}

func TestAddNewDevices(t *testing.T) {

	if err := setup(); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

	out, err := addDevices()
	if err != nil {
		t.Fatal(err)
	}

	err = checkTimestampMap(out, xdpObjects.LastPacketTime)
	if err != nil {
		t.Fatal("checking lastpackettime:", err)
	}

	err = checkTimestampMap(out, xdpObjects.Sessions)
	if err != nil {
		t.Fatal("checking sessions:", err)
	}

	pubs := []database.Device{}
	for _, device := range out {
		if len(config.GetEffectiveAcl(device.Username).Allow) > 0 {
			pubs = append(pubs, device)
		}
	}

	publicAcls, err := checkLPMMap(pubs, xdpObjects.PublicTable)
	if err != nil {
		t.Fatal("checking publictable:", err)
	}

	mfas := []database.Device{}
	for _, device := range out {
		if len(config.GetEffectiveAcl(device.Username).Mfa) > 0 {
			mfas = append(mfas, device)
		}
	}

	mfaAcls, err := checkLPMMap(mfas, xdpObjects.MfaTable)
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

func TestAuthorise(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatal(err)
	}
	defer xdpObjects.Close()

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
		headers[0].String(): 1,
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

		expectedResults[newHeader.String()] = 2

	}

	for i := range headers {
		if headers[i].Src == nil || headers[i].Dst == nil {
			t.Fatal("could not parse ip")
		}

		packet, err := headers[i].Marshal()
		if err != nil {
			t.Fatal(err)
		}

		value, _, err := xdpObjects.XdpProgFunc.Test(packet)
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

		value, _, err := xdpObjects.XdpProgFunc.Test(packet)
		if err != nil {
			t.Fatalf("program failed %s", err)
		}

		if result(value) != "XDP_DROP" {
			t.Fatalf("after deauthenticating, everything should be XDP_DROP instead %s", result(value))
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

func result(code uint32) string {
	switch code {
	case 1:
		return "XDP_DROP"
	case 2:
		return "XDP_PASS"
	default:
		return "XDP_UNKNOWN_UNUSED"
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

func setup() error {
	err := config.Load("../example_config.json")
	if err != nil && !strings.Contains(err.Error(), "Configuration has already been loaded") {

		return err
	}

	return loadXDP()
}
