package router

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I headers

const (
	ebpfFS = "/sys/fs/bpf"
)

const CLOCK_BOOTTIME = uint32(7)

type Timespec struct {
	Ftv_sec  int64
	Ftv_nsec int64
} /* struct_timespec.h:10:1 */

func GetTimeStamp() uint64 {
	var t Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, uintptr(CLOCK_BOOTTIME), uintptr(unsafe.Pointer(&t)), 0)

	return uint64(t.Ftv_sec*int64(time.Second) + t.Ftv_nsec)
}

type device struct {
	sessionExpiry  uint64
	lastPacketTime uint64

	// Hash of username (sha1 20 bytes)
	// Essentially allows us to compress all usernames, if collisions are a problem in the future we'll move to sha256 or xxhash
	user_id [20]byte

	deviceLock uint32
}

func (d device) Size() int {
	return 40 // 8 + 8 + 20 + 4
}

func (d device) Bytes() []byte {

	output := make([]byte, 40)

	binary.LittleEndian.PutUint64(output[0:8], d.sessionExpiry)
	binary.LittleEndian.PutUint64(output[8:16], d.lastPacketTime)

	copy(output[16:36], d.user_id[:])

	binary.LittleEndian.PutUint32(output[36:], d.deviceLock)

	return output
}

func (d *device) Unpack(b []byte) error {
	if len(b) != 40 {
		return errors.New("too short")
	}

	d.sessionExpiry = binary.LittleEndian.Uint64(b[:8])
	d.lastPacketTime = binary.LittleEndian.Uint64(b[8:16])

	copy(d.user_id[:], b[16:36])

	d.deviceLock = binary.LittleEndian.Uint32(b[16:])

	return nil
}

type Key struct {

	// first member must be a prefix u32 wide
	// rest can are arbitrary
	Prefixlen uint32
	IP        net.IP
}

func (l Key) Bytes() []byte {
	output := make([]byte, 8)
	binary.LittleEndian.PutUint32(output[0:4], l.Prefixlen)
	copy(output[4:], l.IP.To4())

	return output
}

func (l *Key) Unpack(b []byte) error {
	if len(b) != 8 {
		return errors.New("too short")
	}

	l.Prefixlen = binary.LittleEndian.Uint32(b[:4])
	l.IP = b[4:]

	return nil
}

func (l Key) String() string {
	return fmt.Sprintf("%s/%d", l.IP.String(), l.Prefixlen)
}

var (
	//Keep reference to xdpLink, otherwise it may be garbage collected
	xdpLink      link.Link
	xdpObjects   bpfObjects
	innerMapSpec *ebpf.MapSpec = &ebpf.MapSpec{
		Name:      "inner_map",
		Type:      ebpf.LPMTrie,
		KeySize:   8, // 4 bytes for prefix, 4 bytes for u32 (ipv4)
		ValueSize: 1, // quasi bool
		// This flag is required for dynamically sized inner maps.
		// Added in linux 5.10.
		Flags: unix.BPF_F_NO_PREALLOC,

		// We set this to 200 now, but this inner map spec gets copied
		// and altered later.
		MaxEntries: 2000,
	}
)

var mapsLookup = map[string]**ebpf.Map{
	"account_locked":  &xdpObjects.AccountLocked,
	"devices":         &xdpObjects.bpfMaps.Devices,
	"inactivity_time": &xdpObjects.InactivityTimeoutMinutes,
	"mfa_table":       &xdpObjects.MfaTable,
	"public_table":    &xdpObjects.PublicTable,
}

func loadXDP() error {

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading spec: %s", err)
	}

	spec.Maps["public_table"].InnerMap = innerMapSpec
	spec.Maps["mfa_table"].InnerMap = innerMapSpec

	// Load pre-compiled programs into the kernel.
	if err = spec.LoadAndAssign(&xdpObjects, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}

	value := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if config.Values().SessionInactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err = xdpObjects.InactivityTimeoutMinutes.Put(uint32(0), value)
	if err != nil {
		return fmt.Errorf("could not set inactivity timeout: %s", err)
	}

	return nil
}

func attachXDP() error {
	iface, err := net.InterfaceByName(config.Values().Wireguard.DevName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", config.Values().Wireguard.DevName, err)
	}

	//Try multiple times to attach program if the link is temporarily busy (work around for link.Close requiring a sleep)
	for i := 0; i < 5; i++ {
		// Attach the program.
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   xdpObjects.bpfPrograms.XdpWagFirewall,
			Interface: iface.Index,
		})

		if err != nil {
			if strings.Contains(err.Error(), "device or resource busy") {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("could not attach XDP program: %s", err)
		} else {
			return nil
		}
	}

	return nil
}

func Pin() error {

	err := xdpLink.Pin(filepath.Join(ebpfFS, "wag_link"))
	if err != nil {
		return err
	}

	return nil
}

func Unpin() error {

	os.Remove(filepath.Join(ebpfFS, "wag_link"))

	if xdpLink != nil {
		return xdpLink.Unpin()
	}

	return nil
}

func loadPins() (err error) {

	defer func() {
		if err != nil {
			xdpObjects.Close()

			if xdpLink != nil {
				log.Println("Unable to reconnect to XDP firewall, flushing (this will cause interruptions, sorry)")
				xdpLink.Close()
			}
		}
	}()

	xdpLink, err = link.LoadPinnedLink(filepath.Join(ebpfFS, "wag_link"), nil)
	if err != nil {
		return err
	}

	Unpin() // Pins should only be loaded once then tied to the life of the program

	i, err := xdpLink.Info()
	if err != nil {
		return err
	}

	xdpObjects.bpfPrograms.XdpWagFirewall, err = ebpf.NewProgramFromID(i.Program)
	if err != nil {
		return err
	}

	programInfo, err := xdpObjects.XdpWagFirewall.Info()
	if err != nil {
		return err
	}

	maps, available := programInfo.MapIDs()
	if !available {
		err = errors.New("kernel is not new enough to load pins")
		return err
	}

	for _, m := range maps {

		var currentMap *ebpf.Map
		currentMap, err = ebpf.NewMapFromID(m)
		if err != nil {
			return err
		}

		var mapInfo *ebpf.MapInfo
		mapInfo, err = currentMap.Info()
		if err != nil {
			return err
		}

		_, ok := mapsLookup[mapInfo.Name]
		if !ok {
			err = errors.New("could not find map " + mapInfo.Name + " in lookup table")
			return
		}

		*mapsLookup[mapInfo.Name] = currentMap
	}

	return nil

}

func setupXDP() error {

	err := loadPins()
	if err == nil {
		// If we can load the pins instead of reattaching to the device, do so
		return nil
	}

	if err := loadXDP(); err != nil {
		return err
	}

	if err := attachXDP(); err != nil {
		return err
	}

	knownDevices, err := data.GetAllDevices()
	if err != nil {
		return err
	}

	for _, device := range knownDevices {
		err := xdpAddDevice(device.Username, device.Address)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetAllAuthorised() ([]string, error) {

	devices, err := data.GetAllDevices()
	if err != nil {
		return nil, err
	}

	result := []string{}
	for _, device := range devices {
		if IsAuthed(device.Address) {
			result = append(result, device.Address)
		}
	}

	return result, nil
}

func IsAuthed(address string) bool {

	ip := net.ParseIP(address)
	//Wasnt able to parse any IP address
	if ip == nil {
		return false
	}

	ip = ip.To4()
	//Unable to get a ipv4 address
	if ip == nil {
		return false
	}

	var isAccountLocked uint32
	if xdpObjects.AccountLocked.Lookup([]byte(ip), &isAccountLocked) != nil {
		return false
	}

	var deviceStruct device
	deviceBytes := make([]byte, deviceStruct.Size())

	if xdpObjects.Devices.Lookup([]byte(ip), deviceBytes) != nil {
		return false
	}

	if deviceStruct.Unpack(deviceBytes) != nil {
		return false
	}

	currentTime := GetTimeStamp()

	sessionValid := deviceStruct.deviceLock != 0 && (deviceStruct.sessionExpiry > currentTime || deviceStruct.sessionExpiry == math.MaxUint64)

	sessionActive := ((currentTime-deviceStruct.lastPacketTime) < uint64(config.Values().SessionInactivityTimeoutMinutes)*60000000000 || config.Values().SessionInactivityTimeoutMinutes < 0)

	return isAccountLocked == 0 && deviceStruct.deviceLock == 0 && sessionValid && sessionActive
}

func xdpRemoveDevice(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Address " + address + " is not parsable as an IP address")
	}

	msg := "remove device failed: "
	var finalError error = errors.New(msg)

	var deviceStruct device
	deviceBytes := make([]byte, deviceStruct.Size())

	deviceTableErr := xdpObjects.Devices.LookupAndDelete(ip.To4(), deviceBytes)
	if deviceTableErr != nil && !strings.Contains(deviceTableErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from devices table failed: " + deviceTableErr.Error() + " ")
	}

	publicErr := xdpObjects.PublicTable.Delete(deviceStruct.user_id)
	if publicErr != nil && !strings.Contains(publicErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from public table failed: " + deviceTableErr.Error() + " ")
	}

	mfaErr := xdpObjects.MfaTable.Delete(deviceStruct.user_id)
	if mfaErr != nil && !strings.Contains(mfaErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from mfa table failed: " + publicErr.Error() + " ")
	}

	if finalError.Error() == msg {
		finalError = nil
	}

	return finalError
}

func xdpAddDevice(username, address string) error {

	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Device " + username + " does not have an internal IP address assigned to it, this is a big bug")
	}

	var deviceStruct device
	deviceBytes := make([]byte, deviceStruct.Size())
	err := xdpObjects.Devices.Lookup(ip.To4(), &deviceBytes)
	if err == nil {
		return errors.New("attempted to add a device with address that already exists")
	}

	//Defaultly add device that is not authenticated
	deviceStruct.lastPacketTime = 0
	deviceStruct.sessionExpiry = 0
	deviceStruct.user_id = sha1.Sum([]byte(username))

	if err := xdpUserExists(deviceStruct.user_id); err != nil {
		return err
	}

	return xdpObjects.Devices.Put(ip.To4(), deviceStruct.Bytes())
}

func xdpAddRoute(username string, table *ebpf.Map, destinations []string) error {

	userid := sha1.Sum([]byte(username))
	var innerMapID ebpf.MapID

	err := table.Lookup(userid, &innerMapID)
	if err != nil {
		return fmt.Errorf("error looking up table: %s", err)
	}

	for _, destination := range destinations {

		k, err := parseIP(destination)
		if err != nil {
			return err
		}

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return fmt.Errorf("inner map: %s", err)
		}

		err = innerMap.Put(k.Bytes(), uint8(1))
		if err != nil {
			return fmt.Errorf("inner map: %s", err)
		}

		innerMap.Close()

	}

	return nil
}

func xdpUserExists(userid [20]byte) error {
	var locked uint32 // Unused
	err := xdpObjects.AccountLocked.Lookup(userid, &locked)
	if err != nil {
		return err
	}

	return nil
}

func xdpAddUser(username string, acls config.Acl) error {

	userid := sha1.Sum([]byte(username))

	if xdpUserExists(userid) != nil {
		return errors.New("user already exists")
	}

	err := xdpObjects.AccountLocked.Put(userid, uint32(0))
	if err != nil {
		return err
	}

	addMap := func(table *ebpf.Map) error {
		inner, err := ebpf.NewMap(innerMapSpec)
		if err != nil {
			return fmt.Errorf("%s creating new map: %s", table.String(), err)
		}

		err = table.Put(userid, uint32(inner.FD()))
		if err != nil {
			return fmt.Errorf("%s adding new map to public table: %s", table.String(), err)
		}

		return inner.Close()
	}

	err = addMap(xdpObjects.PublicTable)
	if err != nil {
		return err
	}

	err = addMap(xdpObjects.MfaTable)
	if err != nil {
		return err
	}

	//Little bit clumsy, but has to be done as there is no bpf_map_get_fd_by_id function in ebpf go style :P

	if err := xdpAddRoute(username, xdpObjects.MfaTable, acls.Mfa); err != nil {
		return err
	}

	if err := xdpAddRoute(username, xdpObjects.PublicTable, acls.Allow); err != nil {
		return err
	}

	return nil
}

func RefreshConfiguration() []error {

	devices, err := data.GetAllDevices()
	if err != nil {
		return []error{err}
	}

	var errors []error

	value := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if config.Values().SessionInactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err = xdpObjects.InactivityTimeoutMinutes.Put(uint32(0), value)
	if err != nil {
		return []error{fmt.Errorf("could not set inactivity timeout: %s", err)}
	}

	for _, device := range devices {
		ip := net.ParseIP(device.Address)
		if ip == nil || ip.To4() == nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: cant parse ip from %s for user %s", device.Address, device.Username))
			continue
		}

		acls := config.GetEffectiveAcl(device.Username)

		err := xdpObjects.PublicTable.Delete(ip.To4())
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: delete public table for %s: %s", device.Username, err.Error()))
			continue
		}

		// Create inner tables for the public and mfa routes based on the current ACLs
		err = xdpCreateUser(ip, xdpObjects.PublicTable, acls.Allow)
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: recreating public table for %s: %s", device.Username, err.Error()))
			continue
		}

		err = xdpObjects.MfaTable.Delete(ip.To4())
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: delete mfa table for %s: %s", device.Username, err.Error()))
			continue
		}

		err = xdpCreateUser(ip, xdpObjects.MfaTable, acls.Mfa)
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: recreate mfa table for %s: %s", device.Username, err.Error()))
			continue
		}

	}

	return errors
}

func SetAuthorized(internalAddress string) error {
	storedDevice, err := data.GetDeviceByAddress(internalAddress)
	if err != nil {
		return err
	}

	var deviceStruct device
	deviceStruct.lastPacketTime = GetTimeStamp()

	deviceStruct.sessionExpiry = GetTimeStamp() + uint64(config.Values().MaxSessionLifetimeMinutes)*60000000000
	if config.Values().MaxSessionLifetimeMinutes < 0 {
		deviceStruct.sessionExpiry = math.MaxUint64 // If the session timeout is disabled, (<0) then we set to max value
	}

	deviceStruct.user_id = sha1.Sum([]byte(storedDevice.Username))

	return xdpObjects.Devices.Update(net.ParseIP(storedDevice.Address).To4(), deviceStruct.Bytes(), ebpf.UpdateExist)
}

func Deauthenticate(address string) error {

	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Unable to get IP address from: " + address)
	}

	if ip.To4() == nil {
		return errors.New("IP address was not ipv4")
	}

	return xdpObjects.Devices.Delete(ip.To4())
}

type FirewallRules struct {
	IsAuthorized        bool
	LastPacketTimestamp uint64
	Expiry              uint64
	MFA                 []string
	Public              []string
}

func GetRules() (map[string]FirewallRules, error) {

	result := make(map[string]FirewallRules)

	authorizedDevices, err := GetAllAuthorised()
	if err != nil {
		return result, err
	}

	users, err := data.GetAllUsers()
	if err != nil {
		return nil, err
	}

	userlookup := map[string]string{}

	for _, user := range users {
		hash := sha1.Sum([]byte(user.Username))
		userlookup[string(hash[:])] = user.Username // Yes I know, problems of my own design
	}

	iterateSubmap := func(innerMapID ebpf.MapID) (result []string, err error) {
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("map from id: %s", err)
		}

		var (
			innerKey []byte
			val      uint8
		)
		innerIter := innerMap.Iterate()
		kv := Key{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)
			result = append(result, kv.String())
		}

		innerMap.Close()

		return
	}

	for _, address := range authorizedDevices {
		fwRule := result[address]
		fwRule.IsAuthorized = true

		ip := net.IP(address)

		var (
			currentDevice device
			innerMapID    ebpf.MapID
		)

		deviceBytes, err := xdpObjects.Devices.LookupBytes(ip.To4())
		if err != nil {
			return nil, err
		}

		err = currentDevice.Unpack(deviceBytes)
		if err != nil {
			return nil, err
		}

		err = xdpObjects.PublicTable.Lookup(currentDevice.user_id, &innerMapID)
		if err == nil {
			if fwRule.Public, err = iterateSubmap(innerMapID); err != nil {
				return nil, err
			}
		}

		err = xdpObjects.MfaTable.Lookup(currentDevice.user_id, &innerMapID)
		if err == nil {
			if fwRule.Public, err = iterateSubmap(innerMapID); err != nil {
				return nil, err
			}
		}

		result[address] = fwRule
	}

	return result, nil
}

func parseIP(address string) (Key, error) {
	address = strings.TrimSpace(address)

	ip, netmask, err := net.ParseCIDR(address)
	if err != nil {
		out := net.ParseIP(address)
		if out != nil {
			return Key{32, out}, nil
		}

		return Key{}, errors.New("could not parse ip from input: " + address)
	}

	ones, _ := netmask.Mask.Size()
	return Key{uint32(ones), ip}, nil
}

func GetBPFHash() string {
	hash := sha256.Sum256(_BpfBytes)
	return hex.EncodeToString(hash[:])
}
