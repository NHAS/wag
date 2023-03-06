package router

import (
	"crypto/sha1"
	"crypto/sha256"
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

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/routetypes"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I headers

const (
	ebpfFS         = "/sys/fs/bpf"
	CLOCK_BOOTTIME = uint32(7)
)

var (

	//Keep reference to xdpLink, otherwise it may be garbage collected
	xdpLink       link.Link
	xdpObjects    bpfObjects
	routesMapSpec *ebpf.MapSpec = &ebpf.MapSpec{
		Name: "routes_map",
		Type: ebpf.LPMTrie,

		// 4 byte, prefix length;
		// 4 byte, ipv4 addr;
		KeySize: 8,

		//policies array
		ValueSize: 8 * 128,

		// This flag is required for dynamically sized inner maps.
		// Added in linux 5.10.
		Flags: unix.BPF_F_NO_PREALLOC,

		// We set this to 200 now, but this inner map spec gets copied
		// and altered later.
		MaxEntries: 1024,
	}

	mapsLookup = map[string]**ebpf.Map{
		"account_locked":  &xdpObjects.AccountLocked,
		"devices":         &xdpObjects.bpfMaps.Devices,
		"inactivity_time": &xdpObjects.InactivityTimeoutMinutes,
		"mfa_table":       &xdpObjects.MfaTable,
		"public_table":    &xdpObjects.PublicTable,
	}
)

type Timespec struct {
	Ftv_sec  int64
	Ftv_nsec int64
} /* struct_timespec.h:10:1 */

func GetTimeStamp() uint64 {
	var t Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, uintptr(CLOCK_BOOTTIME), uintptr(unsafe.Pointer(&t)), 0)

	return uint64(t.Ftv_sec*int64(time.Second) + t.Ftv_nsec)
}

func loadXDP() error {

	err := rlimit.RemoveMemlock()
	if err != nil {
		return err
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading spec: %s", err)
	}

	spec.Maps["public_table"].InnerMap = routesMapSpec
	spec.Maps["mfa_table"].InnerMap = routesMapSpec
	// Load pre-compiled programs into the kernel.
	if err = spec.LoadAndAssign(&xdpObjects, nil); err != nil {

		var ve *ebpf.VerifierError
		b := errors.As(err, &ve)
		if b {
			fmt.Print(strings.Join(ve.Log, "\n"))
			return fmt.Errorf("loading objects: %s", err)
		}

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
		}

		return nil
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

	Unpin() // Pins should only be loaded once tied to the life of the program

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
		return errors.New("xdp setup get all devices: " + err.Error())
	}

	users, err := data.GetAllUsers()
	if err != nil {
		return errors.New("xdp setup get all users: " + err.Error())
	}

	for _, user := range users {

		if err := AddUser(user.Username, config.GetEffectiveAcl(user.Username)); err != nil {
			return errors.New("xdp setup add user: " + err.Error())
		}
	}

	for _, device := range knownDevices {
		err := xdpAddDevice(device.Username, device.Address)
		if err != nil {
			return errors.New("xdp setup add device to user: " + err.Error())
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

// IsAuthed returns true if the device is authorised
func IsAuthed(address string) bool {

	lock.RLock()
	defer lock.RUnlock()

	return isAuthed(address)

}

func isAuthed(address string) bool {
	ip := net.ParseIP(address)
	//Wasnt able to parse any IP address
	if ip == nil {
		return false
	}

	var deviceStruct fwentry

	deviceBytes, err := xdpObjects.Devices.LookupBytes([]byte(ip.To4()))
	if err != nil {
		return false
	}

	if deviceStruct.Unpack(deviceBytes) != nil {
		return false
	}

	var isAccountLocked uint32
	if xdpObjects.AccountLocked.Lookup(deviceStruct.user_id, &isAccountLocked) != nil {
		return false
	}

	currentTime := GetTimeStamp()

	sessionValid := (deviceStruct.sessionExpiry > currentTime || deviceStruct.sessionExpiry == math.MaxUint64)

	sessionActive := ((currentTime-deviceStruct.lastPacketTime) < uint64(config.Values().SessionInactivityTimeoutMinutes)*60000000000 || config.Values().SessionInactivityTimeoutMinutes < 0)

	return isAccountLocked == 0 && sessionValid && sessionActive
}

func xdpRemoveDevice(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Address " + address + " is not parsable as an IP address")
	}

	msg := "remove device failed: "
	var finalError error = errors.New(msg)

	var deviceStruct fwentry
	deviceBytes := make([]byte, deviceStruct.Size())

	deviceTableErr := xdpObjects.Devices.LookupAndDelete(ip.To4(), deviceBytes)
	if deviceTableErr != nil && !strings.Contains(deviceTableErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from devices table failed: " + deviceTableErr.Error() + " ")
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

	var deviceStruct fwentry
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

// Takes the LPM table and associates a route to a policy
func xdpAddRoute(usersRouteTable *ebpf.Map, ruleDefinitions []string) error {

	for _, destination := range ruleDefinitions {

		rules, err := routetypes.ParseRule(destination)
		if err != nil {
			return err
		}

		for i := range rules.Keys {

			err := usersRouteTable.Put(&rules.Keys[i], &rules.Values)
			if err != nil {
				return fmt.Errorf("error putting route key in inner map: %s", err)
			}
		}

	}

	return nil
}

// If err != nil then user does not exist
func xdpUserExists(userid [20]byte) error {

	var locked uint32 // Unused
	err := xdpObjects.AccountLocked.Lookup(userid, &locked)
	if err != nil {
		return err
	}

	return nil
}

func addInnerMapTo(key interface{}, spec *ebpf.MapSpec, table *ebpf.Map) (*ebpf.Map, error) {
	inner, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("%s creating new map: %s", table.String(), err)
	}

	err = table.Put(key, uint32(inner.FD()))
	if err != nil {
		return nil, fmt.Errorf("%s adding new map to table: %s", table.String(), err)
	}

	return inner, nil
}

func AddUser(username string, acls config.Acl) error {

	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))

	if xdpUserExists(userid) == nil {
		return errors.New("user already exists")
	}

	err := xdpObjects.AccountLocked.Put(userid, uint32(0))
	if err != nil {
		return err
	}

	return setMaps(userid, acls)
}

func setMaps(userid [20]byte, acls config.Acl) error {
	// Adds LPM trie to existing map (hashmap to map)
	mfaTable, err := addInnerMapTo(userid, routesMapSpec, xdpObjects.MfaTable)
	if err != nil {
		return err
	}

	publicTable, err := addInnerMapTo(userid, routesMapSpec, xdpObjects.PublicTable)
	if err != nil {
		return err
	}

	if err := xdpAddRoute(mfaTable, acls.Mfa); err != nil {
		return err
	}

	if err := xdpAddRoute(publicTable, acls.Allow); err != nil {
		return err
	}

	return nil
}

func RemoveUser(username string) error {

	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))

	err := xdpObjects.AccountLocked.Delete(userid)
	if err != nil {
		return err
	}

	var finalError error
	publicErr := xdpObjects.PublicTable.Delete(userid)
	if publicErr != nil && !strings.Contains(publicErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from public table failed")
	}

	mfaErr := xdpObjects.MfaTable.Delete(userid)
	if mfaErr != nil && !strings.Contains(mfaErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from mfa table failed: " + publicErr.Error() + " ")
	}

	if finalError != nil {
		return finalError
	}

	return nil
}

// RefreshConfiguration updates acls on all users, and updates the inactivity timeout
func RefreshConfiguration() []error {

	lock.Lock()
	defer lock.Unlock()

	users, err := data.GetAllUsers()
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

	for _, user := range users {
		err := refreshUserAcls(user.Username)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

// Update FW routes for specific user
func RefreshUserAcls(username string) error {

	lock.Lock()
	defer lock.Unlock()

	return refreshUserAcls(username)
}

// Non-mutex guarded internal version
func refreshUserAcls(username string) error {

	userid := sha1.Sum([]byte(username))

	acls := config.GetEffectiveAcl(username)

	return setMaps(userid, acls)
}

// SetAuthroized correctly sets the timestamps for a device with internal IP address as internalAddress
func SetAuthorized(internalAddress, username string) error {

	if net.ParseIP(internalAddress).To4() == nil {
		return errors.New("internalAddress could not be parsed as an IPv4 address")
	}

	lock.Lock()
	defer lock.Unlock()

	var deviceStruct fwentry
	deviceStruct.lastPacketTime = GetTimeStamp()

	deviceStruct.sessionExpiry = GetTimeStamp() + uint64(config.Values().MaxSessionLifetimeMinutes)*60000000000
	if config.Values().MaxSessionLifetimeMinutes < 0 {
		deviceStruct.sessionExpiry = math.MaxUint64 // If the session timeout is disabled, (<0) then we set to max value
	}

	deviceStruct.user_id = sha1.Sum([]byte(username))

	return xdpObjects.Devices.Update(net.ParseIP(internalAddress).To4(), deviceStruct.Bytes(), ebpf.UpdateExist)
}

func Deauthenticate(address string) error {

	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Unable to get IP address from: " + address)
	}

	if ip.To4() == nil {
		return errors.New("IP address was not ipv4")
	}

	lock.Lock()
	defer lock.Unlock()

	deviceBytes, err := xdpObjects.Devices.LookupBytes(ip.To4())
	if err != nil {
		return err
	}

	var devicesStruct fwentry
	err = devicesStruct.Unpack(deviceBytes)
	if err != nil {
		return err
	}

	devicesStruct.lastPacketTime = 0
	devicesStruct.sessionExpiry = 0

	return xdpObjects.Devices.Update(ip.To4(), devicesStruct.Bytes(), ebpf.UpdateExist)
}

type FirewallRules struct {
	MFA           []string
	Public        []string
	Devices       []fwDevice
	AccountLocked uint32
}

type fwDevice struct {
	LastPacketTimestamp uint64
	Expiry              uint64
	IP                  string
	Authorized          bool
}

func GetRoutes(username string) ([]string, error) {
	userid := sha1.Sum([]byte(username))

	result := map[string]bool{}

	iterateSubmap := func(innerMapID ebpf.MapID) (err error) {
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return fmt.Errorf("map from id: %s", err)
		}

		var (
			k        routetypes.Key
			policies [routetypes.MAX_POLICIES]routetypes.Policy
		)
		innerIter := innerMap.Iterate()

		for innerIter.Next(&k, &policies) {
			result[k.String()] = true
		}

		innerMap.Close()

		return
	}

	var innerMapID ebpf.MapID

	err := xdpObjects.PublicTable.Lookup(userid, &innerMapID)
	if err == nil {
		if err = iterateSubmap(innerMapID); err != nil {
			return nil, err
		}
	}

	err = xdpObjects.MfaTable.Lookup(userid, &innerMapID)
	if err == nil {
		if err = iterateSubmap(innerMapID); err != nil {
			return nil, err
		}
	}

	resultArray := make([]string, len(result))
	for k := range result {
		resultArray = append(resultArray, k)
	}

	return resultArray, nil
}

func GetRules() (map[string]FirewallRules, error) {

	lock.RLock()
	defer lock.RUnlock()

	users, err := data.GetAllUsers()
	if err != nil {
		return nil, errors.New("fw rule get all users: " + err.Error())
	}

	// This is less than optimal, but I'd prefer to be using something of static length in the ebpf code, and sha1 is a decent compression algorithm as well
	hashToUsername := make(map[string]string)
	for _, user := range users {
		hash := sha1.Sum([]byte(user.Username))
		hashToUsername[hex.EncodeToString(hash[:])] = user.Username
	}

	result := make(map[string]FirewallRules)

	iterateSubmap := func(innerMapID ebpf.MapID) (result []string, err error) {
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("map from id: %s", err)
		}

		var (
			k        routetypes.Key
			policies [routetypes.MAX_POLICIES]routetypes.Policy
		)
		innerIter := innerMap.Iterate()

		for innerIter.Next(&k, &policies) {
			var actualPolicies []routetypes.Policy
			for i := range policies {
				if policies[i].PolicyType == routetypes.STOP {
					actualPolicies = policies[:i]
					break
				}
			}

			result = append(result, k.String()+" policy "+fmt.Sprintf("%+v", actualPolicies))
		}

		innerMap.Close()

		return
	}

	var deviceStruct fwentry
	deviceBytes := make([]byte, deviceStruct.Size())
	ipBytes := make([]byte, 4)
	iter := xdpObjects.Devices.Iterate()

	for iter.Next(&ipBytes, &deviceBytes) {

		err := deviceStruct.Unpack(deviceBytes)
		if err != nil {
			return nil, err
		}

		res := hashToUsername[hex.EncodeToString(deviceStruct.user_id[:])]

		fwRule := result[res]
		fwRule.Devices = append(fwRule.Devices, fwDevice{IP: net.IP(ipBytes).String(), Authorized: isAuthed(net.IP(ipBytes).String()), Expiry: deviceStruct.sessionExpiry, LastPacketTimestamp: deviceStruct.lastPacketTime})

		if err := xdpObjects.AccountLocked.Lookup(deviceStruct.user_id, &fwRule.AccountLocked); err != nil {
			return nil, err
		}

		var innerMapID ebpf.MapID

		err = xdpObjects.PublicTable.Lookup(deviceStruct.user_id, &innerMapID)
		if err == nil {
			if fwRule.Public, err = iterateSubmap(innerMapID); err != nil {
				return nil, err
			}
		}

		err = xdpObjects.MfaTable.Lookup(deviceStruct.user_id, &innerMapID)
		if err == nil {
			if fwRule.MFA, err = iterateSubmap(innerMapID); err != nil {
				return nil, err
			}
		}

		result[res] = fwRule

	}

	return result, iter.Err()
}

func GetBPFHash() string {
	lock.RLock()
	defer lock.RUnlock()

	hash := sha256.Sum256(_BpfBytes)
	return hex.EncodeToString(hash[:])
}
