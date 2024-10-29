package router

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/gaissmai/bart"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"tailscale.com/net/packet"
)

type Firewall struct {
	sync.RWMutex

	closed bool

	inactivityTimeout time.Duration

	// Username to policy
	userPolicies map[string]*Policies
	userIsLocked map[string]bool

	addressToDevice   map[netip.Addr]*FirewallDevice
	addressToPolicies map[netip.Addr]*Policies
	addressToUser     map[netip.Addr]string

	pubkeyToDevice map[string]*FirewallDevice
	userToDevices  map[string]map[string]*FirewallDevice

	ctrl   *wgctrl.Client
	device *device.Device

	deviceName string

	nodeID types.ID

	challenger *Challenger

	listenerKeys struct {
		Device     string
		Membership string

		Users string
		Acls  string

		Groups  string
		Timeout string
	}

	Verifier *Challenger

	connectedPeersLck       sync.RWMutex
	currentlyConnectedPeers map[string]string
}

func (f *Firewall) GetRoutes(username string) ([]string, error) {
	f.RLock()
	defer f.RUnlock()

	result := make([]string, 0, f.userPolicies[username].policies.Size())
	if _, ok := f.userPolicies[username]; !ok {
		return result, fmt.Errorf("user not found: %q", username)
	}

	f.userPolicies[username].policies.All()(func(pfx netip.Prefix, val *[]routetypes.Policy) bool {
		result = append(result, pfx.String())
		return true
	})

	return result, nil
}

func (f *Firewall) SetInactivityTimeout(inactivityTimeoutMinutes int) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	f.inactivityTimeout = time.Duration(inactivityTimeoutMinutes) * time.Minute

	return nil
}

func (f *Firewall) RefreshUserAcls(username string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	return f._refreshUserAcls(username)
}

func (f *Firewall) _refreshUserAcls(username string) error {

	currentUserPolicies, ok := f.userPolicies[username]
	if !ok {
		return nil
	}
	userAcls := data.GetEffectiveAcl(username)

	rules, errs := routetypes.ParseRules(userAcls.Mfa, userAcls.Allow, userAcls.Deny)
	if len(errs) != 0 {
		log.Println("Parsing rules for user had errors: ", errs)
	}

	// Clear lpm trie
	f.userPolicies[username].policies = &bart.Table[*[]routetypes.Policy]{}

	for _, rule := range rules {
		for i := range rule.Keys {
			currentUserPolicies.Insert(rule.Keys[i].ToPrefix(), &rule.Values)
		}
	}

	return nil

}

func (f *Firewall) Evaluate(src, dst netip.AddrPort, proto uint16) bool {

	if f.closed {
		return false
	}

	// As we are evaluating for a single packet, we can take a snapshot of this current moment
	// Yes I know there is a pointer that may be modified, but its largely fine
	f.RLock()
	targetAddr := &dst
	deviceAddr := &src
	policies, ok := f.addressToPolicies[src.Addr()]
	if !ok || policies == nil {
		policies, ok = f.addressToPolicies[dst.Addr()]
		if !ok || policies == nil {
			f.RUnlock()
			return false
		}

		deviceAddr = &dst
		targetAddr = &src
	}

	policy := policies.tableLookup(targetAddr.Addr())
	if policy == nil {
		f.RUnlock()
		return false
	}

	authorized := f.isAuthed(deviceAddr.Addr())

	// It doesnt matter if this gets race conditioned
	device := f.addressToDevice[deviceAddr.Addr()]
	if device != nil && time.Since(device.lastPacketTime) < f.inactivityTimeout {
		device.lastPacketTime = time.Now()
	} else {
		authorized = false
	}

	f.RUnlock()

	action := false
	for _, decision := range *policy {

		//      ANY = 0
		//      If we match the protocol,
		//      If type is SINGLE and the port is either any, or equal
		//      OR
		//      If type is RANGE and the port is within bounds
		if (decision.Proto == routetypes.ANY || decision.Proto == proto) &&
			((decision.Is(routetypes.SINGLE) && (decision.LowerPort == routetypes.ANY || decision.LowerPort == targetAddr.Port())) ||
				(decision.Is(routetypes.RANGE) && (decision.LowerPort <= targetAddr.Port() && decision.UpperPort >= targetAddr.Port()))) {

			if decision.Is(routetypes.DENY) {
				return false
			} else if decision.Is(routetypes.PUBLIC) {

				action = true
			} else {
				action = authorized
				if !action {
					return false
				}
			}
		}

	}

	return action
}

func (f *Firewall) UpdateNodeAssociation(device data.Device) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	// If the peer roams away from us, unset the endpoint in wireguard to make sure the peer watcher will absolutely register a change if they roam back
	var endpoint *net.UDPAddr = nil

	if device.AssociatedNode == data.GetServerID() {
		endpoint = device.Endpoint
	}

	err := f.setPeerEndpoint(device, endpoint)
	if err != nil {
		return err
	}

	address, err := netip.ParseAddr(device.Address)
	if err != nil {
		return err
	}

	d, ok := f.addressToDevice[address]
	if !ok {
		return fmt.Errorf("device %q was not found", address)
	}

	d.associatedNode = device.AssociatedNode

	return nil
}

func (f *Firewall) SetAuthorized(address string, node types.ID) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	netipAddr, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}

	device, ok := f.addressToDevice[netipAddr]
	if !ok {
		return fmt.Errorf("device %q was not found", address)
	}

	maxSession, err := data.GetSessionLifetimeMinutes()
	if err != nil {
		return err
	}

	device.sessionExpiry = time.Now().Add(time.Duration(maxSession) * time.Minute)
	device.lastPacketTime = time.Now()
	device.associatedNode = node

	return nil
}

func (f *Firewall) Deauthenticate(address string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("failed to parse address as netip.Addr: %s", err)
	}

	return f._deauthenticate(addr)
}

func (f *Firewall) _deauthenticate(address netip.Addr) error {

	device, ok := f.addressToDevice[address]
	if !ok {
		return fmt.Errorf("device %q was not found", address)
	}

	device.sessionExpiry = time.Time{}
	device.lastPacketTime = time.Time{}

	return nil
}

func (f *Firewall) DeauthenticateAllDevices(username string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	for _, device := range f.userToDevices[username] {
		err := f._deauthenticate(device.address)
		if err != nil {
			return fmt.Errorf("failed to deauthenticate all devices: %s", err)
		}
	}

	return nil
}

func (f *Firewall) AddUser(username string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	if _, ok := f.userIsLocked[username]; ok {
		return errors.New("user already exists")
	}

	// New users are obviously unlocked
	f.userIsLocked[username] = false
	f.userPolicies[username] = new(Policies)

	f.userToDevices[username] = make(map[string]*FirewallDevice)

	return f._refreshUserAcls(username)
}

func (f *Firewall) Test(packetBytes []byte) bool {

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)

	p.Decode(packetBytes)

	return f.Evaluate(p.Src, p.Dst, uint16(p.IPProto))
}

func (f *Firewall) RefreshConfiguration() []error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return []error{errors.New("firewall instance has been closed")}
	}

	allUsers, err := data.GetAllUsers()
	if err != nil {
		return []error{err}
	}

	inactivityTimeoutMinutes, err := data.GetSessionInactivityTimeoutMinutes()
	if err != nil {
		return []error{err}
	}

	f.inactivityTimeout = time.Duration(inactivityTimeoutMinutes) * time.Minute

	var allErrors []error
	for _, user := range allUsers {
		f.userIsLocked[user.Username] = user.Locked
		if err := f._refreshUserAcls(user.Username); err != nil {
			allErrors = append(allErrors, err)
		}
	}

	return allErrors
}

func (f *Firewall) RemoveUser(username string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	delete(f.userIsLocked, username)
	delete(f.userPolicies, username)

	for _, d := range f.userToDevices[username] {

		f._removePeer(d.public.String(), d.address.String())
	}
	delete(f.userToDevices, username)

	return nil
}

func (f *Firewall) GetAllAuthorised() ([]string, error) {
	f.RLock()
	defer f.RUnlock()

	if f.closed {
		return nil, errors.New("firewall instance has been closed")
	}

	result := []string{}
	for addr, device := range f.addressToDevice {
		if f.isAuthed(addr) {
			result = append(result, device.address.String())
		}
	}

	return result, nil
}

// IsAuthed returns true if the device is authorised
func (f *Firewall) IsAuthed(address string) bool {
	f.RLock()
	defer f.RUnlock()

	if f.closed {
		return false
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}

	return f.isAuthed(addr)
}

func (f *Firewall) isAuthed(addr netip.Addr) bool {

	ok := f.userIsLocked[addr.String()]
	if !ok {
		return false
	}

	device, ok := f.addressToDevice[addr]
	if !ok {
		return false
	}

	if device.associatedNode != f.nodeID {
		return false
	}

	// If the device has been inactive
	if device.lastPacketTime.Add(f.inactivityTimeout).Before(time.Now()) {
		return false
	}

	return device.isAuthed()
}

func (f *Firewall) SetLockAccount(username string, locked bool) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	_, ok := f.userIsLocked[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}

	f.userIsLocked[username] = locked
	if locked {
		for _, device := range f.userToDevices[username] {
			device.sessionExpiry = time.Time{}
		}
	}
	return nil

}

type fwDevice struct {
	LastPacketTimestamp time.Time
	Expiry              time.Time
	IP                  string
	Authorized          bool
	AssociatedNode      string
}

type FirewallRules struct {
	Policies      []string
	Devices       []fwDevice
	AccountLocked bool
}

func (f *Firewall) GetRules() (map[string]FirewallRules, error) {
	f.RLock()
	defer f.RUnlock()

	users, err := data.GetAllUsers()
	if err != nil {
		return nil, errors.New("fw rule get all users: " + err.Error())
	}

	result := make(map[string]FirewallRules)

	for _, user := range users {
		r := FirewallRules{}

		for _, device := range f.userToDevices[user.Username] {
			dto := device.toDTO()
			dto.Authorized = f.isAuthed(device.address)
			r.Devices = append(r.Devices, dto)
		}

		f.userPolicies[user.Username].policies.All()(func(pfx netip.Prefix, val *[]routetypes.Policy) bool {

			strPfx := pfx.String()
			for _, v := range *val {
				r.Policies = append(r.Policies, fmt.Sprintf("%s %s", strPfx, v.String()))
			}

			return true
		})

		r.AccountLocked = f.userIsLocked[user.Username]
		result[user.Username] = r
	}

	return result, nil
}

type FirewallDevice struct {
	sync.RWMutex

	public wgtypes.Key

	// The internal vpn address the device occupies
	address netip.Addr

	lastPacketTime time.Time
	sessionExpiry  time.Time

	associatedNode types.ID

	username string
}

func (fwd *FirewallDevice) toDTO() fwDevice {
	return fwDevice{
		LastPacketTimestamp: fwd.lastPacketTime,
		Expiry:              fwd.sessionExpiry,

		IP: fwd.address.String(),
	}
}

func (d *FirewallDevice) isAuthed() bool {
	t := time.Now()
	return !d.sessionExpiry.Equal(time.Time{}) &&
		t.Before(d.sessionExpiry)

}

type Policies struct {
	sync.RWMutex

	policies *bart.Table[*[]routetypes.Policy]
}

func (table *Policies) Insert(prefix netip.Prefix, policy *[]routetypes.Policy) {
	table.Lock()
	defer table.Unlock()

	table.policies.Insert(prefix, policy)
}

func (table *Policies) Lookup(ip netip.Addr) *[]routetypes.Policy {
	table.RLock()
	defer table.RUnlock()

	return table.tableLookup(ip)
}

func (table *Policies) LookupBytes(ip []byte) *[]routetypes.Policy {
	table.RLock()
	defer table.RUnlock()

	var n netip.Addr
	switch len(ip) {
	case net.IPv4len:
		n = netip.AddrFrom4([net.IPv4len]byte(ip))
	case net.IPv6len:
		n = netip.AddrFrom16([net.IPv6len]byte(ip))
	default:
		panic(errors.New("looking up unknown address length/type"))
	}

	return table.tableLookup(n)
}

func (table *Policies) tableLookup(ip netip.Addr) *[]routetypes.Policy {
	policy, _ := table.policies.Lookup(ip)
	return policy

}
