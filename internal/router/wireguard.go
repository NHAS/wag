package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/mdlayher/netlink"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"golang.org/x/sys/unix"
	"tailscale.com/net/packet"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

type Wrapper struct {
	tun.Device

	eventsUpDown chan tun.Event
	// eventsOther yields non-up-and-down tun.Events that arrive on a Wrapper's events channel.
	eventsOther chan tun.Event

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}

	fw *Firewall

	closeOnce sync.Once
}

func NewWrap(tdev tun.Device, fw *Firewall) *Wrapper {
	w := &Wrapper{
		Device: tdev,
		closed: make(chan struct{}),

		eventsUpDown: make(chan tun.Event),
		eventsOther:  make(chan tun.Event),
		fw:           fw,
	}

	go w.pumpEvents()

	return w
}

// EventsUpDown returns a TUN event channel that contains all Up and Down events.
func (t *Wrapper) EventsUpDown() chan tun.Event {
	return t.eventsUpDown
}

// Events returns a TUN event channel that contains all non-Up, non-Down events.
// It is named Events because it is the set of events that we want to expose to wireguard-go,
// and Events is the name specified by the wireguard-go tun.Device interface.
func (t *Wrapper) Events() <-chan tun.Event {
	return t.eventsOther
}

func (t *Wrapper) pumpEvents() {
	defer close(t.eventsUpDown)
	defer close(t.eventsOther)
	src := t.Device.Events()
	for {
		// Retrieve an event from the TUN device.
		var event tun.Event
		var ok bool
		select {
		case <-t.closed:
			return
		case event, ok = <-src:
			if !ok {
				return
			}
		}

		// Pass along event to the correct recipient.
		// Though event is a bitmask, in practice there is only ever one bit set at a time.
		dst := t.eventsOther
		if event&(tun.EventUp|tun.EventDown) != 0 {
			dst = t.eventsUpDown
		}
		select {
		case <-t.closed:
			return
		case dst <- event:
		}
	}
}

func (t *Wrapper) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.Device.Close()
	})
	return err
}

// Read from the OS tun device
func (t *Wrapper) Read(buffs [][]byte, sizes []int, offset int) (int, error) {

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)

	n, err := t.Device.Read(buffs, sizes, offset)
	if err != nil {
		return n, err
	}

	placement := 0
	for i := 0; i < n; i++ {
		p.Decode(buffs[i][offset : offset+sizes[i]])

		if t.fw.Evaluate(p.Src, p.Dst, uint16(p.IPProto)) {

			log.Println("adding to buffer")
			buffs[placement] = buffs[i]
			sizes[placement] = sizes[i]
			placement++
		}
	}

	buffs = buffs[:placement]
	if len(buffs) == 0 {
		return 0, nil
	}

	return placement, err
}

// Write to the OS tun device i.e going from wireguard peer -> real world
func (t *Wrapper) Write(buffs [][]byte, offset int) (int, error) {

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)

	i := 0
	for _, buff := range buffs {
		p.Decode(buff[offset:])

		if t.fw.Evaluate(p.Src, p.Dst, uint16(p.IPProto)) {

			log.Println("adding to buffer write")

			buffs[i] = buff
			i++
		}
	}

	buffs = buffs[:i]
	if len(buffs) == 0 {
		return 0, nil
	}

	_, err := t.Device.Write(buffs, offset)

	return len(buffs), err
}

func (f *Firewall) endpointChange(e device.Event) {
	switch e.Type {
	case device.EventEndpointChange:

		k, err := wgtypes.NewKey(e.Pk[:])
		if err != nil {
			panic(err)
		}

		device, ok := f.pubkeyToDevice[k.String()]
		if !ok {
			log.Println("found unknown device,", k.String())
			return
		}

		addrPort, err := netip.ParseAddrPort(e.Endpoint)
		if err != nil {
			log.Println("invalid endpoint string: ", err, e.Endpoint)
			return
		}

		udpAddr := net.UDPAddrFromAddrPort(addrPort)

		f.connectedPeersLck.Lock()
		defer f.connectedPeersLck.Unlock()

		// If the peer address has changed, but is not empty (empty indicates the peer has changed it node association away from this node)
		if f.currentlyConnectedPeers[device.address.String()] != udpAddr.String() {
			f.currentlyConnectedPeers[device.address.String()] = udpAddr.String()

			// Otherwise, just update the node association
			err = data.UpdateDeviceConnectionDetails(device.address.String(), udpAddr)
			if err != nil {
				log.Printf("unable to update device (%s:%s) endpoint: %s", device.address, device.username, err)
			}

		}

	default:
		log.Println("unknown event type: ", e.Type)
	}
}

func (f *Firewall) setupWireguard() error {

	// open TUN device

	tdev, err := tun.CreateTUN(config.Values.Wireguard.DevName, config.Values.Wireguard.MTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN device:  path: %q mtu: %d, err %v", config.Values.Wireguard.DevName, config.Values.Wireguard.MTU, err)
	}

	uapiInterfaceName := config.Values.Wireguard.DevName
	realInterfaceName, err2 := tdev.Name()
	if err2 == nil {
		uapiInterfaceName = realInterfaceName
	}

	logger := device.NewLogger(
		device.LogLevelError,
		fmt.Sprintf("(%s) ", uapiInterfaceName),
	)

	// open UAPI file

	fileUAPI, err := ipc.UAPIOpen(uapiInterfaceName)
	if err != nil {
		return fmt.Errorf("UAPI listen error: %v", err)
	}

	tdev = NewWrap(tdev, f)
	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	device.SetEventHandler(f.endpointChange)

	logger.Verbosef("Wireguard Device started")

	errs := make(chan error)

	uapi, err := ipc.UAPIListen(config.Values.Wireguard.DevName, fileUAPI)
	if err != nil {
		return fmt.Errorf("failed to listen on uapi socket: %v", err)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	err = func(network string) error {

		conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
		if err != nil {
			return err
		}
		defer conn.Close()

		ip, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return err
		}

		ipNet.IP = ip

		err = f.setIp(conn, config.Values.Wireguard.DevName, *ipNet)
		if err != nil {
			return err
		}

		return f.setUp(conn, config.Values.Wireguard.DevName)
	}(config.Values.Wireguard.Address)
	if err != nil {
		return fmt.Errorf("unable to set wireguard tunnel ip: %s", err)
	}

	err = device.Up()
	if err != nil {
		return fmt.Errorf("unable to bring wireguard device up: %s", err)
	}

	go func() {

		// wait for device to be closed
		select {
		case <-errs:
		case <-device.Wait():
		}

		// clean up
		uapi.Close()
		device.Close()

		logger.Verbosef("Shutting down")
	}()
	return nil
}

func (f *Firewall) setupUsers(users []data.UserModel) error {

	var errs []error

	for _, user := range users {
		err := f.AddUser(user.Username)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f *Firewall) setupDevices(devices []data.Device) error {
	f.Lock()
	defer f.Unlock()

	var c wgtypes.Config

	err := f.setupWireguard()
	if err != nil {
		return fmt.Errorf("failed to create wireguard device: err: %s", err)
	}

	key, err := wgtypes.ParseKey(config.Values.Wireguard.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse wireguard private key: err: %s", err)
	}
	c.PrivateKey = &key

	port := config.Values.Wireguard.ListenPort
	c.ListenPort = &port

	for _, device := range devices {
		pk, _ := wgtypes.ParseKey(device.Publickey)
		var psk *wgtypes.Key = nil

		testKey, err := wgtypes.ParseKey(device.PresharedKey)
		if device.PresharedKey != "unset" && err == nil {
			psk = &testKey
		}

		_, network, _ := net.ParseCIDR(device.Address + "/32")

		pc := wgtypes.PeerConfig{
			PublicKey:         pk,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*network},
			PresharedKey:      psk,
		}

		if device.AssociatedNode == data.GetServerID() {
			pc.Endpoint = device.Endpoint
		}

		if config.Values.Wireguard.ServerPersistentKeepAlive > 0 {
			d := time.Duration(config.Values.Wireguard.ServerPersistentKeepAlive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}

		err = f._addPeerToMaps(pk, device.Username, device.Address, device.AssociatedNode)
		if err != nil {
			return err
		}

		c.Peers = append(c.Peers, pc)
	}

	f.ctrl, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("cannot start wireguard control: err: %s", err)
	}

	err = f.ctrl.ConfigureDevice(config.Values.Wireguard.DevName, c)
	if err != nil {
		return fmt.Errorf("cannot configure wireguard device: err: %s", err)

	}

	return nil
}

func (f *Firewall) setUp(c *netlink.Conn, interfaceName string) error {

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("wireguard network iface %s does not exist: %s", interfaceName, err)
	}

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWLINK,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	msg := &IfInfomsg{
		Family: unix.AF_UNSPEC,
		Change: unix.IFF_UP,
		Flags:  unix.IFF_UP,
	}

	msg.Index = int32(iface.Index)

	req.Data = msg.Serialize()

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}

	}

	return nil
}

func (f *Firewall) setIp(c *netlink.Conn, name string, address net.IPNet) error {

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWADDR,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("wireguard network iface %s does not exist: %s", name, err)
	}

	addrMsg := IfAddrmsg{
		Family: unix.AF_INET,
		Index:  uint32(iface.Index),
	}

	preflen, _ := address.Mask.Size()
	addrMsg.Prefixlen = uint8(preflen)

	req.Data = addrMsg.Serialize()

	ne := netlink.NewAttributeEncoder()
	ne.Bytes(unix.IFA_LOCAL, address.IP[:4])

	msg, err := ne.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode af: %v", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}
	}

	return nil
}

func (f *Firewall) ServerDetails() (key wgtypes.Key, port int, err error) {
	if f.closed {
		return key, 0, errors.New("firewall instance has been closed")
	}

	ctr, err := wgctrl.New()
	if err != nil {
		return key, port, fmt.Errorf("cannot start wireguard control %v", err)
	}
	defer ctr.Close()

	dev, err := ctr.Device(config.Values.Wireguard.DevName)
	if err != nil {
		return key, port, fmt.Errorf("unable to start wireguard-ctrl on device with name %s: %v", config.Values.Wireguard.DevName, err)
	}

	return dev.PublicKey, dev.ListenPort, nil
}

func (f *Firewall) setPeerEndpoint(device data.Device, endpoint *net.UDPAddr) error {

	id, err := wgtypes.ParseKey(device.Publickey)
	if err != nil {
		return err
	}

	var c wgtypes.Config
	c.Peers = []wgtypes.PeerConfig{
		{
			UpdateOnly: true,
			PublicKey:  id,
			Endpoint:   endpoint,
		},
	}

	err = f.ctrl.ConfigureDevice(config.Values.Wireguard.DevName, c)
	if err != nil {
		return err
	}

	return nil
}

// Remove a wireguard peer from firewall and wg device
func (f *Firewall) RemovePeer(publickey, address string) error {
	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	return f._removePeer(publickey, address)
}

func (f *Firewall) _removePeer(publickey, address string) error {

	addressNetAddr, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("address %q could not be parsed to netip.Addr for removal: %s", address, err)
	}

	pubkey, err := wgtypes.ParseKey(publickey)
	if err != nil {
		return fmt.Errorf("could not parse %q as wireguard public key for removal: %s", publickey, err)
	}

	deviceToRemove, ok := f.addressToDevice[addressNetAddr]
	if !ok {
		// If the device has already been removed, ignore this
		// Happens if we delete a user, then etcd registers the device key has been deleted
		return nil
	}

	delete(f.pubkeyToDevice, deviceToRemove.public.String())

	delete(f.addressToPolicies, deviceToRemove.address)
	delete(f.addressToDevice, deviceToRemove.address)
	delete(f.addressToUser, deviceToRemove.address)

	userdevices := f.userToDevices[deviceToRemove.username]
	delete(userdevices, address)
	f.userToDevices[deviceToRemove.username] = userdevices

	var c wgtypes.Config
	c.Peers = append(c.Peers, wgtypes.PeerConfig{
		PublicKey: pubkey,
		Remove:    true,
	})

	// Try all removals, if any work then the device is effectively blocked
	err = f.ctrl.ConfigureDevice(config.Values.Wireguard.DevName, c)
	if err != nil {
		return fmt.Errorf("failed to remove wireguard peer %q from wireguard device: %s", address, err)
	}

	return nil
}

// Takes the device to replace and returns the address of said device
func (f *Firewall) ReplacePeer(device data.Device, newPublicKey wgtypes.Key) error {

	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	addressesMap, ok := f.userToDevices[device.Username]
	if !ok {
		return fmt.Errorf("user %q not found when replacing peer %q", device.Username, device.Address)
	}

	currentDevice, ok := addressesMap[device.Address]
	if !ok {
		return fmt.Errorf("device %q does not exist", device.Address)
	}

	//As the api for managing wireguard has no "update public key" function we have to do it manually remove -> add
	oldPublicKey, err := wgtypes.ParseKey(device.Publickey)
	if err != nil {
		return err
	}

	var c wgtypes.Config
	c.Peers = append(c.Peers, wgtypes.PeerConfig{
		PublicKey: oldPublicKey,
		Remove:    true,
	})

	err = f.ctrl.ConfigureDevice(config.Values.Wireguard.DevName, c)
	if err != nil {
		return err
	}

	_, network, err := net.ParseCIDR(device.Address + "/32")
	if err != nil {
		return err
	}

	c.Peers = []wgtypes.PeerConfig{
		{
			PublicKey:         newPublicKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*network},
		},
	}

	err = f.ctrl.ConfigureDevice(config.Values.Wireguard.DevName, c)
	if err != nil {
		return err
	}

	currentDevice.public = newPublicKey

	return nil
}

func (f *Firewall) ListPeers() ([]wgtypes.Peer, error) {

	f.Lock()
	defer f.Unlock()

	if f.closed {
		return nil, errors.New("firewall instance has been closed")
	}

	dev, err := f.ctrl.Device(f.deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get wireguard device: %q, err %v", f.deviceName, err)
	}

	return dev.Peers, err
}

// AddPeer adds the device to wireguard
func (f *Firewall) AddPeer(public wgtypes.Key, username, address, presharedKey string, node types.ID) (err error) {

	f.Lock()
	defer f.Unlock()

	if f.closed {
		return errors.New("firewall instance has been closed")
	}

	preshared_key, err := wgtypes.ParseKey(presharedKey)
	if err != nil {
		return err
	}

	_, network, err := net.ParseCIDR(address + "/32")
	if err != nil {
		return err
	}

	var c wgtypes.Config
	c.Peers = []wgtypes.PeerConfig{
		{
			PublicKey:         public,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*network},
			PresharedKey:      &preshared_key,
		},
	}

	err = f.ctrl.ConfigureDevice(f.deviceName, c)
	if err != nil {
		return fmt.Errorf("failed to add new wireguard peer: %s", err)
	}

	return f._addPeerToMaps(public, username, address, node)
}

func (f *Firewall) _addPeerToMaps(public wgtypes.Key, username, address string, node types.ID) error {
	addressNetAddr, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("address %q could not be parsed to netip addr: %s", address, err)
	}

	addressesMap, ok := f.userToDevices[username]
	if !ok {
		return fmt.Errorf("user %q not found when adding peer %q", username, address)
	}

	if _, ok := addressesMap[address]; ok {
		return fmt.Errorf("address %q already exists for user %q", address, username)
	}

	device := FirewallDevice{
		public:         public,
		address:        addressNetAddr,
		associatedNode: node,
		username:       username,
		lastPacketTime: time.Time{},
		sessionExpiry:  time.Time{}, // Todo take this from db

	}

	addressesMap[address] = &device
	f.userToDevices[username] = addressesMap

	f.addressToDevice[addressNetAddr] = &device
	f.pubkeyToDevice[public.String()] = &device

	f.addressToPolicies[addressNetAddr] = f.userPolicies[username]

	f.addressToUser[addressNetAddr] = username

	return nil
}
