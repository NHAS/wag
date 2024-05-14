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
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/NHAS/wag/internal/acls"
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

		// We set this to 1024 now, but this inner map spec gets copied
		// and altered later.
		MaxEntries: 1024,
	}

	userPolicyMaps = map[[20]byte]*ebpf.Map{}

	// Pain
	usersToAddresses = map[string]map[string]string{}
	addressesToUsers = map[string]string{}
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

	spec.Maps["policies_table"].InnerMap = routesMapSpec
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

	err = xdpObjects.NodeId.Put(uint32(0), uint64(data.GetServerID()))
	if err != nil {
		return fmt.Errorf("could not set node id: %s", err)
	}

	sessionInactivityTimeoutMinutes, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return err
	}

	value := uint64(sessionInactivityTimeoutMinutes) * 60000000000
	if sessionInactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err = xdpObjects.InactivityTimeoutMinutes.Put(uint32(0), value)
	if err != nil {
		return fmt.Errorf("could not set inactivity timeout: %s", err)
	}

	return nil
}

func attachXDP() error {
	iface, err := net.InterfaceByName(config.Values.Wireguard.DevName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", config.Values.Wireguard.DevName, err)
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

func setupXDP(users []data.UserModel, knownDevices []data.Device) error {
	if err := loadXDP(); err != nil {
		return err
	}

	if err := attachXDP(); err != nil {
		return err
	}

	errs := bulkCreateUserMaps(users)
	if len(errs) != 0 {
		return fmt.Errorf("%s", errs)
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

	inactivityTimeoutMinutes, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return false
	}

	currentTime := GetTimeStamp()

	sessionValid := (deviceStruct.sessionExpiry > currentTime || deviceStruct.sessionExpiry == math.MaxUint64)

	sessionActive := ((currentTime-deviceStruct.lastPacketTime) < uint64(inactivityTimeoutMinutes)*60000000000 || inactivityTimeoutMinutes < 0)

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

func xdpAddDevice(username, address string, associatedNode uint64) error {

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
	deviceStruct.associatedNode = associatedNode

	if err := xdpUserExists(deviceStruct.user_id); err != nil {
		return err
	}

	return xdpObjects.Devices.Put(ip.To4(), deviceStruct.Bytes())
}

func SetLockAccount(username string, locked uint32) error {
	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))

	for address := range usersToAddresses[username] {
		err := _deauthenticate(address)
		if err != nil {
			log.Println(err)
		}
	}

	err := xdpObjects.AccountLocked.Put(userid, &locked)
	if err != nil {
		return err
	}

	return nil
}

// Takes the LPM table and associates a route to a policy
func xdpAddRoute(usersRouteTable *ebpf.Map, userAcls acls.Acl) error {

	rules, errs := routetypes.ParseRules(userAcls.Mfa, userAcls.Allow, userAcls.Deny)
	if len(errs) != 0 {
		log.Println("Parsing rules for user had errors: ", errs)
	}

	for _, rule := range rules {
		for i := range rule.Keys {

			err := usersRouteTable.Put(&rule.Keys[i], &rule.Values)
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

func AddUser(username string, acls acls.Acl) error {

	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))
	if xdpUserExists(userid) == nil {
		return errors.New("user already exists")
	}

	// New users are obviously unlocked
	err := xdpObjects.AccountLocked.Put(userid, uint32(0))
	if err != nil {
		return err
	}

	err = setSingleUserMap(userid, acls)
	if err != nil {
		return err
	}

	usersToAddresses[username] = make(map[string]string)

	return nil
}

func setSingleUserMap(userid [20]byte, acls acls.Acl) error {
	// Adds LPM trie to existing map (hashmap to map)
	// Or if we have an existing map, update it

	if _, ok := userPolicyMaps[userid]; !ok {
		policiesInnerTable, err := ebpf.NewMap(routesMapSpec)
		if err != nil {
			return fmt.Errorf("%s creating new map: %s", xdpObjects.PoliciesTable.String(), err)
		}

		err = xdpObjects.PoliciesTable.Update(userid, uint32(policiesInnerTable.FD()), ebpf.UpdateNoExist)
		if err != nil {
			return fmt.Errorf("%s adding new map to table: %s", xdpObjects.PoliciesTable.String(), err)
		}

		userPolicyMaps[userid] = policiesInnerTable
	}

	mapRef := userPolicyMaps[userid]
	if err := clearPolicyMap(mapRef); err != nil {
		return err
	}

	if err := xdpAddRoute(mapRef, acls); err != nil {
		return err
	}

	return nil
}

func clearPolicyMap(toClear *ebpf.Map) error {
	var (
		lastKey []byte
		err     error
	)

	// Due to type inference we cant just set lastKey to nil to get the first key
	lastKey, err = toClear.NextKeyBytes(nil)
	if err != nil {
		return err
	}

	for {

		if lastKey == nil {
			return nil
		}

		err = toClear.Delete(lastKey)
		if err != nil && err != ebpf.ErrKeyNotExist {
			return err
		}

		lastKey, err = toClear.NextKeyBytes(lastKey)
		if err != nil {
			return err
		}
	}
}

// I've tried my hardest not to make this stateful. But alas we must cache the user policy maps or things become unreasonbly slow
// If someone has a better way of doing this. Please for the love of god pipe up
// https://github.com/cilium/ebpf/discussions/1297
func bulkCreateUserMaps(users []data.UserModel) []error {

	var (
		keys   [][20]byte
		values []uint32
		errors []error

		maps = map[string]*ebpf.Map{}
	)

	for _, user := range users {
		userid := sha1.Sum([]byte(user.Username))

		// Fast path, if the user already has a map then just repopulate the map. Since we have "stop" rules at the end of definitions it doesnt matter if other rules were defined
		// This speeds up things like refresh acls, but not wag start up
		if policiesInnerTable, ok := userPolicyMaps[userid]; ok {

			if err := clearPolicyMap(policiesInnerTable); err != nil {
				errors = append(errors, err)
				continue
			}

			err := xdpAddRoute(policiesInnerTable, data.GetEffectiveAcl(user.Username))

			if err != nil {
				errors = append(errors, err)
			}
		}

		locked := uint32(0)
		if user.Locked {
			locked = 1
		}

		err := xdpObjects.AccountLocked.Put(userid, locked)
		if err != nil {
			return []error{err}
		}

		policiesInnerTable, err := ebpf.NewMap(routesMapSpec)
		if err != nil {
			return []error{fmt.Errorf("%s creating new map: %s", xdpObjects.PoliciesTable.String(), err)}
		}

		values = append(values, uint32(policiesInnerTable.FD()))
		keys = append(keys, userid)
		maps[user.Username] = policiesInnerTable

		userPolicyMaps[userid] = policiesInnerTable

	}

	n, err := xdpObjects.PoliciesTable.BatchUpdate(keys, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateNoExist),
	})

	if err != nil {
		return []error{fmt.Errorf("%s adding new map to table: %s", xdpObjects.PoliciesTable.String(), err)}
	}

	if n != len(keys) {
		return []error{fmt.Errorf("batch update could not write all keys to map: expected %d got %d", len(keys), n)}
	}

	// As we created maps for this, we dont need to clear things
	for username, m := range maps {
		err := xdpAddRoute(m, data.GetEffectiveAcl(username))
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

func RemoveUser(username string) error {

	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))

	err := xdpObjects.AccountLocked.Delete(userid)
	if err != nil {
		return err
	}

	err = xdpObjects.PoliciesTable.Delete(userid)
	if err != nil && !strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
		return errors.New("removing user from policies table failed: " + err.Error())
	}

	delete(userPolicyMaps, userid)

	for address, publicKey := range usersToAddresses[username] {
		err = _removePeer(publicKey, address)
		if err != nil {
			log.Println("unable to remove peer: ", address, err)
		}
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

	inactivityTimeoutMinutes, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return []error{err}
	}

	err = setInactivityTimeout(inactivityTimeoutMinutes)
	if err != nil {
		return []error{err}
	}

	return bulkCreateUserMaps(users)
}

func SetInactivityTimeout(inactivityTimeoutMinutes int) error {
	lock.Lock()
	defer lock.Unlock()

	return setInactivityTimeout(inactivityTimeoutMinutes)
}

func setInactivityTimeout(inactivityTimeoutMinutes int) error {
	value := uint64(inactivityTimeoutMinutes) * 60000000000
	if inactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err := xdpObjects.InactivityTimeoutMinutes.Put(uint32(0), value)
	if err != nil {
		return fmt.Errorf("could not set inactivity timeout: %s", err)
	}

	return nil
}

// Update FW routes for specific user
func RefreshUserAcls(username string) error {

	lock.Lock()
	defer lock.Unlock()

	userid := sha1.Sum([]byte(username))

	acls := data.GetEffectiveAcl(username)

	return setSingleUserMap(userid, acls)
}

// SetAuthroized correctly sets the timestamps for a device with internal IP address as internalAddress
func SetAuthorized(internalAddress, username string, node uint64) error {

	if net.ParseIP(internalAddress).To4() == nil {
		return errors.New("internalAddress could not be parsed as an IPv4 address")
	}

	lock.Lock()
	defer lock.Unlock()

	var deviceStruct fwentry
	deviceStruct.lastPacketTime = GetTimeStamp()
	deviceStruct.associatedNode = node

	maxSession, err := data.GetSessionLifetimeMinutes()
	if err != nil {
		return err
	}

	deviceStruct.sessionExpiry = GetTimeStamp() + uint64(maxSession)*60000000000
	if maxSession < 0 {
		deviceStruct.sessionExpiry = math.MaxUint64 // If the session timeout is disabled, (<0) then we set to max value
	}

	deviceStruct.user_id = sha1.Sum([]byte(username))

	return xdpObjects.Devices.Update(net.ParseIP(internalAddress).To4(), deviceStruct.Bytes(), ebpf.UpdateExist)
}

func Deauthenticate(address string) error {

	lock.Lock()
	defer lock.Unlock()

	return _deauthenticate(address)
}

func DeauthenticateAllDevices(username string) error {
	lock.Lock()
	defer lock.Unlock()

	for address := range usersToAddresses[username] {
		err := _deauthenticate(address)
		if err != nil {
			return err
		}
	}

	return nil
}

func _deauthenticate(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Unable to get IP address from: " + address)
	}

	if ip.To4() == nil {
		return errors.New("IP address was not ipv4")
	}

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
	Policies      []string
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

	lock.RLock()
	defer lock.RUnlock()

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

	err := xdpObjects.PoliciesTable.Lookup(userid, &innerMapID)
	if err == nil {
		if err = iterateSubmap(innerMapID); err != nil {
			return nil, err
		}
	}

	resultArray := make([]string, 0, len(result))
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

	iterateSubmap := func(innerMapID ebpf.MapID) (rules []string, err error) {
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

			rules = append(rules, k.String()+" policy "+fmt.Sprintf("%+v", actualPolicies))
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

		res, ok := hashToUsername[hex.EncodeToString(deviceStruct.user_id[:])]
		if !ok {
			log.Println("[ERROR] Device links to unknown user UI (not found in db): ", hex.EncodeToString(deviceStruct.user_id[:]))
			continue
		}

		fwRule := result[res]
		fwRule.Devices = append(fwRule.Devices, fwDevice{IP: net.IP(ipBytes).String(), Authorized: isAuthed(net.IP(ipBytes).String()), Expiry: deviceStruct.sessionExpiry, LastPacketTimestamp: deviceStruct.lastPacketTime})

		if err := xdpObjects.AccountLocked.Lookup(deviceStruct.user_id, &fwRule.AccountLocked); err != nil {
			log.Println("[ERROR] User ID was not properly in firewall map: ", hex.EncodeToString(deviceStruct.user_id[:]), " err: ", err)
			continue
		}

		var innerMapID ebpf.MapID

		err = xdpObjects.PoliciesTable.Lookup(deviceStruct.user_id, &innerMapID)
		if err == nil {
			fwRule.Policies, err = iterateSubmap(innerMapID)
			if err != nil {
				log.Println("[ERROR] User had no policies: ", hex.EncodeToString(deviceStruct.user_id[:]), " err: ", err)
				continue
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
