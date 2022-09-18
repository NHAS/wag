package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"wag/config"
	"wag/database"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

/*
#include <time.h>
static unsigned long long C_GetTimeStamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

func GetTimeStamp() uint64 {
	return uint64(C.C_GetTimeStamp())
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS tc bpf.c -- -I headers

var (
	//Keep reference to xdpLink, otherwise it may be garbage collected
	xdpLink      link.Link
	objs         tcObjects
	innerMapSpec *ebpf.MapSpec
)

func loadXDP() error {
	spec, err := loadTc()
	if err != nil {
		return fmt.Errorf("loading spec: %s", err)
	}

	innerMapSpec = &ebpf.MapSpec{
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

	spec.Maps["public_table"].InnerMap = innerMapSpec
	spec.Maps["mfa_table"].InnerMap = innerMapSpec

	// Load pre-compiled programs into the kernel.
	if err = spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}

	value := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if config.Values().SessionInactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err = objs.InactivityTimeoutMinutes.Put(uint32(0), value)
	if err != nil {
		return fmt.Errorf("could not set inactivity timeout: %s", err)
	}

	return nil
}

func attachXDP() error {

	wgInterface, err := netlink.LinkByName(config.Values().WgDevName)
	if err != nil {
		return fmt.Errorf("cannot find %s: %v", config.Values().WgDevName, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: wgInterface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("cannot add clsact qdisc: %v", err)
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: wgInterface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.tcPrograms.TcIngress.FD(),
		Name:         "wag-ingress-tc",
		DirectAction: true,
	}

	err = netlink.FilterAdd(ingressFilter)
	if err != nil {
		return fmt.Errorf("cannot add ingress filter: %v", err)
	}

	return nil
}

func setupXDP() error {

	if err := loadXDP(); err != nil {
		return err
	}

	if err := attachXDP(); err != nil {
		return err
	}

	knownDevices, err := database.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range knownDevices {
		err := xdpAddDevice(device)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetAllAuthorised() (map[string]uint64, error) {
	result := make(map[string]uint64)

	var ipBytes []byte
	var timestamp uint64

	sessionsIter := objs.Sessions.Iterate()
	for sessionsIter.Next(&ipBytes, &timestamp) {
		ip := net.IP(ipBytes)

		currentTimestamp := GetTimeStamp()

		if timestamp > currentTimestamp {
			result[ip.String()] = timestamp - currentTimestamp
		}
	}

	return result, sessionsIter.Err()
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

	var timestamp uint64
	if objs.Sessions.Lookup([]byte(ip), &timestamp) != nil {
		return false
	}

	var lastPacket uint64
	if objs.LastPacketTime.Lookup([]byte(ip), &lastPacket) != nil {
		return false
	}

	currentTime := GetTimeStamp()

	sessionValid := timestamp != 0 && (timestamp > currentTime || timestamp == math.MaxUint64)

	sessionActive := lastPacket != 0 && ((currentTime-lastPacket) < uint64(config.Values().SessionInactivityTimeoutMinutes)*60000000000 || config.Values().SessionInactivityTimeoutMinutes < 0)

	return sessionValid && sessionActive
}

func xdpRemoveDevice(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Address " + address + " is not parsable as an IP address")
	}

	msg := "remove device failed: "
	var finalError error = errors.New(msg)

	sessionErr := objs.Sessions.Delete(ip.To4())
	if sessionErr != nil && !strings.Contains(sessionErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from session table failed: " + sessionErr.Error() + " ")
	}

	publicErr := objs.PublicTable.Delete(ip.To4())
	if publicErr != nil && !strings.Contains(publicErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from public table failed: " + sessionErr.Error() + " ")
	}

	mfaErr := objs.MfaTable.Delete(ip.To4())
	if mfaErr != nil && !strings.Contains(mfaErr.Error(), ebpf.ErrKeyNotExist.Error()) {
		finalError = errors.New(finalError.Error() + "removing from mfa table failed: " + sessionErr.Error() + " ")
	}

	if finalError.Error() == msg {
		finalError = nil
	}

	return finalError
}

func xdpAddDevice(device database.Device) error {

	ip := net.ParseIP(device.Address)
	if ip == nil {
		return errors.New("Device " + device.Username + " does not have an internal IP address assigned to it, this is a big bug")
	}

	var timestamp uint64
	err := objs.Sessions.Lookup(ip.To4(), &timestamp)
	if err == nil {
		return errors.New("attempted to add a device with address that already exists")
	}

	defer func() {
		//On error of any of the following operations, remove any bits that previous operations were able to add
		if err != nil {
			xdpRemoveDevice(device.Address)
		}
	}()

	acls := config.GetEffectiveAcl(device.Username)

	// Create inner tables for the public and mfa routes based on the current ACLs
	err = xdpCreateRoutes(ip, objs.PublicTable, acls.Allow)
	if err != nil {
		return err
	}

	err = xdpCreateRoutes(ip, objs.MfaTable, acls.Mfa)
	if err != nil {
		return err
	}

	//Defaultly add device that is not authenticated
	err = objs.Sessions.Put(ip.To4(), uint64(0))
	if err != nil {
		return err
	}

	return objs.LastPacketTime.Put(ip.To4(), uint64(0))
}

func xdpCreateRoutes(src net.IP, table *ebpf.Map, destinations []string) error {

	if src == nil {
		return errors.New("IP address was nil")
	}

	if src.To4() == nil {
		return errors.New("unable to get ipv4 address from supplied ip")
	}

	var innerMapID ebpf.MapID
	err := table.Lookup([]byte(src.To4()), &innerMapID)
	if err != nil {
		if strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
			inner, err := ebpf.NewMap(innerMapSpec)
			if err != nil {
				return fmt.Errorf("create new map: %s", err)
			}
			defer inner.Close()

			err = table.Put([]byte(src.To4()), uint32(inner.FD()))
			if err != nil {
				return fmt.Errorf("put outer: %s", err)
			}

			//Little bit clumsy, but has to be done as there is no bpf_map_get_fd_by_id function in ebpf go style :P
			err = table.Lookup([]byte(src.To4()), &innerMapID)
			if err != nil {
				return fmt.Errorf("lookup inner: %s", err)
			}

		} else {
			return fmt.Errorf("lookup outer: %s", err)
		}
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
		defer innerMap.Close()

		err = innerMap.Put(k.Bytes(), uint8(1))
		if err != nil {
			return fmt.Errorf("inner map: %s", err)
		}

	}

	return nil
}

func RefreshConfiguration() []error {

	devices, err := database.GetDevices()
	if err != nil {
		return []error{err}
	}

	var errors []error

	value := uint64(config.Values().SessionInactivityTimeoutMinutes) * 60000000000
	if config.Values().SessionInactivityTimeoutMinutes < 0 {
		value = math.MaxUint64
	}

	err = objs.InactivityTimeoutMinutes.Put(uint32(0), value)
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

		err := objs.PublicTable.Delete(ip.To4())
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: delete public table for %s: %s", device.Username, err.Error()))
			continue
		}

		// Create inner tables for the public and mfa routes based on the current ACLs
		err = xdpCreateRoutes(ip, objs.PublicTable, acls.Allow)
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: recreating public table for %s: %s", device.Username, err.Error()))
			continue
		}

		err = objs.MfaTable.Delete(ip.To4())
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: delete mfa table for %s: %s", device.Username, err.Error()))
			continue
		}

		err = xdpCreateRoutes(ip, objs.MfaTable, acls.Mfa)
		if err != nil {
			errors = append(errors, fmt.Errorf("acl refresh failed: recreate mfa table for %s: %s", device.Username, err.Error()))
			continue
		}

	}

	return errors
}

func SetAuthorized(internalAddress string) error {
	ip := net.ParseIP(internalAddress)
	if ip == nil {
		return errors.New("Unable to get IP address from: " + internalAddress)
	}

	if ip.To4() == nil {
		return errors.New("IP address was not ipv4")
	}

	mfaTimeout := GetTimeStamp() + uint64(config.Values().MaxSessionLifetimeMinutes)*60000000000
	if config.Values().MaxSessionLifetimeMinutes < 0 {
		mfaTimeout = math.MaxUint64 // If the session timeout is disabled, (<0) then we set to max value
	}

	err := objs.Sessions.Update(ip.To4(), mfaTimeout, ebpf.UpdateExist)
	if err != nil {
		return err
	}

	return objs.LastPacketTime.Update(ip.To4(), GetTimeStamp(), ebpf.UpdateExist)
}

func Deauthenticate(address string) error {

	ip := net.ParseIP(address)
	if ip == nil {
		return errors.New("Unable to get IP address from: " + address)
	}

	if ip.To4() == nil {
		return errors.New("IP address was not ipv4")
	}

	objs.LastPacketTime.Update(ip.To4(), uint64(0), ebpf.UpdateExist)

	return objs.Sessions.Update(ip.To4(), uint64(0), ebpf.UpdateExist)
}

type description struct {
	IsAuthorized        bool
	Expires             uint64
	LastPacketTimestamp uint64
	MFA                 []string
	Public              []string
}

func GetRules() (map[string]description, error) {

	result := make(map[string]description)

	m, err := GetAllAuthorised()
	if err != nil {
		return result, err
	}

	for ip, timestamp := range m {
		d := result[ip]

		d.IsAuthorized = true
		d.Expires = timestamp

		result[ip] = d
	}

	var innerMapID ebpf.MapID
	var ipBytes []byte
	var val uint64

	lastPacket := objs.LastPacketTime.Iterate()
	for lastPacket.Next(&ipBytes, &val) {
		ip := net.IP(ipBytes)

		d := result[ip.String()]

		d.LastPacketTimestamp = val

		result[ip.String()] = d
	}

	if lastPacket.Err() != nil {
		return nil, lastPacket.Err()
	}

	publicRoutesIter := objs.PublicTable.Iterate()
	for publicRoutesIter.Next(&ipBytes, &innerMapID) {
		ip := net.IP(ipBytes)

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("map from id: %s", err)
		}

		d := result[ip.String()]

		var innerKey []byte
		var val uint8
		innerIter := innerMap.Iterate()
		kv := Key{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)

			d.Public = append(d.Public, kv.String())
		}
		innerMap.Close()

		result[ip.String()] = d
	}

	if publicRoutesIter.Err() != nil {
		return nil, publicRoutesIter.Err()
	}

	mfaRoutesIter := objs.MfaTable.Iterate()
	for mfaRoutesIter.Next(&ipBytes, &innerMapID) {

		ip := net.IP(ipBytes)

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("map from id: %s", err)
		}

		d := result[ip.String()]

		var innerKey []byte
		var val uint8
		innerIter := innerMap.Iterate()
		kv := Key{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)

			d.MFA = append(d.MFA, kv.String())
		}
		innerMap.Close()

		result[ip.String()] = d
	}

	return result, mfaRoutesIter.Err()
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
