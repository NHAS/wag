package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"wag/config"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I headers

var (
	//Keep reference to xdpLink, otherwise it may be garbage collected
	xdpLink      link.Link
	xdpObjects   bpfObjects
	innerMapSpec *ebpf.MapSpec
)

func setupXDP() error {
	iface, err := net.InterfaceByName(config.Values().WgDevName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", config.Values().WgDevName, err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading spec: %s", err)
	}

	innerMapSpec = &ebpf.MapSpec{
		Name:      "inner_map",
		Type:      ebpf.LPMTrie,
		KeySize:   8, // 4 bytes for prefix, 4 bytes for u32 (ipv4)
		ValueSize: 1, // 1 byte for u8, quasi bool

		// This flag is required for dynamically sized inner maps.
		// Added in linux 5.10.
		Flags: unix.BPF_F_NO_PREALLOC,

		// We set this to 200 now, but this inner map spec gets copied
		// and altered later.
		MaxEntries: 2000,
	}

	spec.Maps["allowance_table"].InnerMap = innerMapSpec

	// Load pre-compiled programs into the kernel.
	if err = spec.LoadAndAssign(&xdpObjects, nil); err != nil {
		return fmt.Errorf("loading objects: %s", err)
	}

	// Attach the program.
	xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   xdpObjects.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("could not attach XDP program: %s", err)
	}

	return nil
}

func xdpAdd(bucket net.IP, key Key) error {

	var innerMapID ebpf.MapID
	err := xdpObjects.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
	if err != nil {
		if strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
			inner, err := ebpf.NewMap(innerMapSpec)
			if err != nil {
				return fmt.Errorf("create new map: %s", err)
			}
			defer inner.Close()

			err = xdpObjects.AllowanceTable.Put([]byte(bucket.To4()), uint32(inner.FD()))
			if err != nil {
				return fmt.Errorf("put outer: %s", err)
			}

			//Little bit clumbsy, but has to be done as there is no bpf_map_get_fd_by_id function in ebpf go style :P
			err = xdpObjects.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
			if err != nil {
				return fmt.Errorf("lookup inner: %s", err)
			}

		} else {
			return fmt.Errorf("lookup outer: %s", err)
		}
	}

	innerMap, err := ebpf.NewMapFromID(innerMapID)
	if err != nil {
		return fmt.Errorf("inner map: %s", err)
	}

	err = innerMap.Put(key.Bytes(), uint8(1))
	if err != nil {
		return fmt.Errorf("inner map: %s", err)
	}

	innerMap.Close()

	return nil
}

func xdpRemoveEntry(bucket net.IP, key Key) error {

	var innerMapID ebpf.MapID
	err := xdpObjects.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
	if err != nil {
		if strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
			return fmt.Errorf("lookup inner: %s", err)
		}
	}

	inner, err := ebpf.NewMapFromID(innerMapID)
	if err != nil {
		return fmt.Errorf("create new map: %s", err)
	}

	err = inner.Delete(key.Bytes())
	if err != nil {
		inner.Close()

		return fmt.Errorf("inner delete: %s", err)
	}

	inner.Close()

	return nil
}

func RemoveAllRoutes(address string) error {
	bucket := net.ParseIP(address)
	if bucket == nil {
		return errors.New("could not parse ip address: " + address)
	}

	err := xdpObjects.AllowanceTable.Delete([]byte(bucket.To4()))
	if err != nil {
		return fmt.Errorf("outer delete: %s", err)
	}

	return nil
}

func GetRules() (map[string][]string, error) {
	var (
		key        []byte
		innerMapID ebpf.MapID
	)

	result := make(map[string][]string)

	iter := xdpObjects.AllowanceTable.Iterate()
	for iter.Next(&key, &innerMapID) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return nil, fmt.Errorf("map from id: %s", err)
		}

		var innerKey []byte
		var val uint8
		innerIter := innerMap.Iterate()
		kv := Key{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)

			result[sourceIP.String()] = append(result[sourceIP.String()], kv.String())
		}
		innerMap.Close()

	}
	return result, iter.Err()
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
