package router

import (
	"errors"
	"fmt"
	"io"
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

// FirewallInterface defines the contract for firewall operations including
// route checking, user management, device authentication, and WireGuard peer management.
// These function should not modify the etcd database, except for updating node association.
type FirewallInterface interface {
	// CheckRoute validates if a specific IPv4 route is allowed for a device,
	// Parameters:
	//   - device: The device IP addresss
	//   - dst: Destination IP address
	//   - proto: Protocol type (e.g., "tcp", "udp", "icmp")
	//   - port: Destination port number
	// Returns:
	//   - decision: Action to take ("error", "passed", "dropped")
	//   - err: Error if creating the packet to send for testing fails
	CheckRoute(device string, dst net.IP, proto string, port int) (decision string, err error)

	// GetRoutes retrieves all allowed routes for a specific user.
	// Parameters:
	//   - username: The username to get routes for
	// Returns:
	//   - []string: List of ip subnets as strings (e.g., "192.168.1.0/24", "10.0.0.0/8")
	//   - error: Error if user was not found in the users policy table (i.e they do not exist)
	GetRoutes(username string) ([]string, error)

	// SetInactivityTimeout configures the timeout period for inactive connections.
	// Parameters:
	//   - inactivityTimeoutMinutes: Timeout duration in minutes, time.Duration(inactivityTimeoutMinutes) * time.Minute
	// Returns:
	//   - error: Will only error if the firewall has already been closed
	SetInactivityTimeout(inactivityTimeoutMinutes int) error

	// RefreshUserAcls reloads a users subnets after getting acls from the etcd database
	// This will skip dns entries that cannot be resolved and emitt an error to stdout and cluster (RaiseError)
	// This is typically called when user permissions change.
	// Parameters:
	//   - username: The username whose ACLs should be refreshed
	// Returns:
	//   - error: Can only error if the firewall is closed (TODO make this a tad better)
	RefreshUserAcls(username string) error

	// Evaluate do the firewall part of wag, check packets within the users ACLs and try and do it as fast as possible
	// it also takes into account whether the user is authorised, or if their session has expired.
	// Parameters:
	//   - src: Source address and port
	//   - dst: Destination address and port
	//   - proto: Protocol number (6 for TCP, 17 for UDP)
	// Returns:
	//   - bool: true if packet should be allowed, false if dropped
	Evaluate(src, dst netip.AddrPort, proto uint16) bool

	// UpdateNodeAssociation updates the device wag node, so that users can roam between wag nodes.
	// This is used to maintain device-to-node mappings for routing decisions.
	// Parameters:
	//   - device: User device to update
	// Returns:
	//   - error: Error if association update fails, or if device isnt found, or device data is corrupt
	UpdateNodeAssociation(device data.Device) error

	// SetAuthorized marks a device as authorized and updates wag node association.
	// Parameters:
	//   - address: IP address as string
	//   - node: Wag node ID that the user device has just authorised on
	// Returns:
	//   - error: Error if ip is invalid, or if the database is sad, or device does not exist in memory
	SetAuthorized(address string, node types.ID) error

	// Deauthenticate removes authentication for a specific device address.
	// The device will no longer be able to access MFA market network routes.
	// Also resets all expiry times
	// Parameters:
	//   - address: Device IP address to deauth
	// Returns:
	//   - error: Error if device isnt found, or if the address is bad.
	Deauthenticate(address string) error

	// DeauthenticateAllDevices removes authentication for all devices belonging to a user.
	// This is typically used when a user account is locked.
	// Parameters:
	//   - username: Username whose devices should be deauthenticated
	// Returns:
	//   - error: Error if user was not found
	DeauthenticateAllDevices(username string) error

	// AddUser creates a new user in the firewall system. You need to add a device individually.
	// This creates an empty policies table (nothing allowed), add adds an empty devices table
	// Parameters:
	//   - username: Username to create
	// Returns:
	//   - error: Error if user already exists, or firewall is closed
	AddUser(username string) error

	// Test evaluates a raw packet against the current firewall rules.
	// Used for testing and debugging firewall behavior.
	// Parameters:
	//   - packetBytes: Raw packet bytes to test
	// Returns:
	//   - bool: true if packet would be allowed, false if dropped
	Test(packetBytes []byte) bool

	// RefreshConfiguration reloads all users acls and inactivity timeout.
	// This applies any configuration changes that were made externally.
	// Returns:
	//   - []error: List of errors encountered during refreshing all users acls (empty if successful)
	RefreshConfiguration() []error

	// RemoveUser deletes a user.
	// This also deauthenticates all of the user's devices.
	// Parameters:
	//   - username: Username to remove
	// Returns:
	//   - error: Error if deleting peers fails
	RemoveUser(username string) error

	// GetAllAuthorised retrieves a list of all currently authorized device addresses.
	// Returns:
	//   - []string: List of authorized addresses
	//   - error: Error if firewall is closed
	GetAllAuthorised() ([]string, error)

	// IsAuthed checks if a specific address is currently authenticated.
	// Parameters:
	//   - address: Wag device IP address
	// Returns:
	//   - bool: true if authenticated, false otherwise, if the ip address is not parsable it will also be false
	IsAuthed(address string) bool

	// SetLockAccount locks or unlocks a user account.
	// Locked accounts cannot authenticate new devices and existing sessions will start dropping MFA routed packets.
	// Parameters:
	//   - username: Username to lock/unlock
	//   - locked: true to lock account, false to unlock
	// Returns:
	//   - error: Error if firewall is closed or if the user does not exist
	SetLockAccount(username string, locked bool) error

	// GetRules retrieves the all current firewall ACLs for every user.
	// Returns:
	//   - map[string]FirewallRules: Rules mapped by username or category
	//   - error: Error if rule retrieval fails
	GetRules() (map[string]FirewallRules, error)

	// Close gracefully shuts down the firewall interface and releases resources.
	// This should be called before application termination.
	Close()

	// ServerDetails returns WireGuard server configuration details.
	// Returns:
	//   - key: Server's public key
	//   - port: Server listening port
	//   - err: Error if server details retrieval fails
	ServerDetails() (key wgtypes.Key, port int, err error)

	// RemovePeer removes a deivce peer from the server configuration.
	// Parameters:
	//   - publickey: Peer's wireguard public key
	//   - address: Peer's IP address
	// Returns:
	//   - error: Error if peer removal fails
	RemovePeer(publickey, address string) error

	// ReplacePeer replaces an existing peer's public key with a new one.
	// Parameters:
	//   - device: Device information for the peer to replace
	//   - newPublicKey: New public key to assign to the peer
	// Returns:
	//   - error: Error if peer replacement fails
	ReplacePeer(device data.Device, newPublicKey wgtypes.Key) error

	// ListPeers retrieves all currently configured WireGuard peers.
	// This is similar to the output of wg
	// Returns:
	//   - []wgtypes.Peer: List of peer configurations, this contains real ip, public key and tx/rx
	//   - error: Error if peer listing fails
	ListPeers() ([]wgtypes.Peer, error)

	// AddPeer adds a new WireGuard peer to the server configuration.
	// Parameters:
	//   - public: Peer's wireguard public key
	//   - username: Associated username for the peer
	//   - address: IP address to assign to the peer (typically determined by etcd)
	//   - presharedKey: Optional pre-shared key for additional security (can be empty)
	//   - node: Node ID to associate with this peer
	// Returns:
	//   - err: Error if peer addition fails
	AddPeer(public wgtypes.Key, username, address, presharedKey string, node types.ID) (err error)
}

type Firewall struct {
	sync.RWMutex

	closed      bool
	hasIptables bool

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

	watchers []io.Closer

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

	if inactivityTimeoutMinutes < 0 {
		f.inactivityTimeout = -1
	} else {
		f.inactivityTimeout = time.Duration(inactivityTimeoutMinutes) * time.Minute
	}

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
		data.RaiseError(errors.Join(errs...), []byte("Could not refresh all acls for user: "+username))
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
	if device != nil && (f.inactivityTimeout == -1 || time.Since(device.lastPacketTime) < f.inactivityTimeout) {
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

	if device.AssociatedNode == data.GetServerID() {
		// TODO figure out a better way of doing this
		// when a client shifts over to us, make sure we set the last packet time to something they can actually use
		d.lastPacketTime = time.Now()
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

	device.disableSessionExpiry = maxSession < 0

	timeToSet := maxSession
	if !device.disableSessionExpiry {
		// when the session expiry is set, it doesnt matter what we set this to, it just cant be the time.Time{} zero value ( as that indicates unauthed)
		timeToSet = 1
	}

	device.sessionExpiry = time.Now().Add(time.Duration(timeToSet) * time.Minute)

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

	err = f._deauthenticate(addr)

	return err
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

	errs := []error{}
	for _, device := range f.userToDevices[username] {
		err := f._deauthenticate(device.address)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
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
	if f.closed {
		return false
	}

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

	if inactivityTimeoutMinutes < 0 {
		f.inactivityTimeout = -1
	} else {
		f.inactivityTimeout = time.Duration(inactivityTimeoutMinutes) * time.Minute
	}

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

	errs := []error{}
	for _, d := range f.userToDevices[username] {
		errs = append(errs, f._removePeer(d.public.String(), d.address.String()))
	}
	delete(f.userToDevices, username)

	return errors.Join(errs...)
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

	device, ok := f.addressToDevice[addr]
	if !ok {
		return false
	}

	if device.associatedNode != f.nodeID {
		return false
	}

	// If the device has been inactive
	if f.inactivityTimeout > 0 && device.lastPacketTime.Add(f.inactivityTimeout).Before(time.Now()) {
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
	LastPacketTimestamp time.Time `json:"last_packet_timestamp"`
	Expiry              time.Time `json:"expiry"`
	IP                  string    `json:"policies"`
	Authorized          bool      `json:"authorized"`
	AssociatedNode      string    `json:"associated_node"`
}

type FirewallRules struct {
	Policies      []string   `json:"policies"`
	Devices       []fwDevice `json:"devices"`
	AccountLocked bool       `json:"account_locked"`
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

	disableSessionExpiry bool
	sessionExpiry        time.Time

	associatedNode types.ID

	username string
}

func (fwd *FirewallDevice) toDTO() fwDevice {
	return fwDevice{
		LastPacketTimestamp: fwd.lastPacketTime,
		Expiry:              fwd.sessionExpiry,
		AssociatedNode:      fwd.associatedNode.String(),
		IP:                  fwd.address.String(),
	}
}

func (d *FirewallDevice) isAuthed() bool {
	t := time.Now()

	return !d.sessionExpiry.Equal(time.Time{}) &&
		(t.Before(d.sessionExpiry) || d.disableSessionExpiry)

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
