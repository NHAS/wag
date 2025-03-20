package mfaportal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/resources"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// https://github.com/gorilla/websocket/blob/main/examples/chat/client.go
const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	readWait = 30 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

type Challenger struct {
	sync.RWMutex
	closing bool

	connections map[string]*websocket.Conn

	listenerKeys []string

	firewall *router.Firewall
}

func NewChallenger(firewall *router.Firewall) (*Challenger, error) {
	r := &Challenger{
		firewall:    firewall,
		connections: make(map[string]*websocket.Conn),
	}

	var err error
	deviceKey, err := data.RegisterEventListener(data.DevicesPrefix, true, r.deviceChanges)
	if err != nil {
		return nil, err
	}
	r.listenerKeys = append(r.listenerKeys, deviceKey)

	sessionsKey, err := data.RegisterEventListener(data.DeviceSessionPrefix, true, r.sessionChanges)
	if err != nil {
		return nil, err
	}
	r.listenerKeys = append(r.listenerKeys, sessionsKey)

	return r, nil
}

func (c *Challenger) Close() error {
	c.Lock()
	defer c.Unlock()
	c.closing = true

	for _, conn := range c.connections {
		go conn.Close(websocket.StatusGoingAway, "Going away")
	}
	clear(c.connections)

	errs := []error{}
	for _, l := range c.listenerKeys {
		err := data.DeregisterEventListener(l)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (c *Challenger) sessionChanges(_ string, current, previous data.DeviceSession, et data.EventType) error {

	switch et {
	case data.DELETED:
		c.UpdateState(current.Address)
	}

	return nil
}

func (c *Challenger) deviceChanges(_ string, current, previous data.Device, et data.EventType) error {

	lockout, err := data.GetLockout()
	if err != nil {
		return fmt.Errorf("cannot get lockout: %s", err)
	}

	sendUpdate := false

	switch et {
	case data.DELETED:
		c.Disconnect(current.Address, "Device deleted.", true)
	case data.MODIFIED:
		// If the real world ip endpoint has changed
		if current.Endpoint.String() != previous.Endpoint.String() {
			sendUpdate = true
			// If we have a challenge on that device (i.e we've deauthed it recently because of network move)
			if err := current.ChallengeExists(); err == nil {
				c.Challenge(current.Username, current.Address)
			}
		}

		if current.Attempts != previous.Attempts &&
			(
			// If the device has become locked
			current.Attempts > lockout ||
				// if the device has become unlocked
				current.Attempts < lockout) {

			sendUpdate = true
		}

		// If we've explicitly deauthorised a device (logout)
		if !current.Authorised.Equal(previous.Authorised) && current.Authorised.IsZero() {
			sendUpdate = true
		}

		if data.HasDeviceAuthorised(current, previous) {
			c.NotifyOfAuth(current)
			// Notify auth sends a state update with it
			sendUpdate = false
		}
	}

	if sendUpdate {
		c.UpdateState(current.Address)
	}

	return nil

}

func (c *Challenger) Challenge(username, address string) error {

	conn := c.getConnection(address)
	if conn == nil {
		return errors.New("connection wasnt found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err := wsjson.Write(ctx, conn, Challenge())
	cancel()
	if err != nil {
		c.Disconnect(address, "Bad connection", false)
		return err
	}

	potentialChallenge, err := ReadChallenge(conn, readWait)
	if err != nil {
		c.Disconnect(address, "No challenge response", false)
		return err
	}

	// Lets make sure people cant auth if they're already authed and extend their session time for no reason
	if potentialChallenge.Challenge != "" && !c.firewall.IsAuthed(address) {

		err = data.ValidateChallenge(username, address, potentialChallenge.Challenge)
		if err != nil {
			log.Println("client failed challenge: ", err)
		} else {
			err = data.AuthoriseDevice(username, address)
			if err != nil {
				log.Println("User device had correct challenge, but cluster failed to authorise: ", err)
			}
		}
	}

	return nil
}

func (c *Challenger) getMfaMethods() []MFAMethod {
	authenticators := authenticators.GetAllEnabledMethods()
	names := []MFAMethod{}
	for _, a := range authenticators {
		names = append(names, MFAMethod{
			FriendlyName: a.FriendlyName(),
			Method:       a.Type(),
		})
	}
	return names
}

func (c *Challenger) createInfoDTO(address string) (UserInfoDTO, error) {
	device, err := data.GetDeviceByAddress(address)
	if err != nil {
		return UserInfoDTO{}, err
	}

	user, err := users.GetUser(device.Username)
	if err != nil {
		return UserInfoDTO{}, err
	}

	defaultMFAMethod, err := data.GetDefaultMfaMethod()
	if err != nil {
		return UserInfoDTO{}, err
	}

	lockout, err := data.GetLockout()
	if err != nil {
		return UserInfoDTO{}, fmt.Errorf("failed to get lockout for updating client: %w", err)
	}

	info := UserInfoDTO{
		Type:                Info,
		Version:             resources.Version(),
		UserMFAMethod:       user.GetMFAType(),
		HelpMail:            data.GetHelpMail(),
		DefaultMFAMethod:    defaultMFAMethod,
		AvailableMfaMethods: c.getMfaMethods(),
		AccountLocked:       user.Locked,
		DeviceLocked:        device.Attempts > lockout,
		Registered:          user.Enforcing,
		Username:            user.Username,
		Authorised:          c.firewall.IsAuthed(address),
	}

	return info, nil
}

func (c *Challenger) getConnection(address string) *websocket.Conn {
	c.RLock()
	defer c.RUnlock()

	conn, ok := c.connections[address]
	if !ok {
		return nil
	}

	return conn
}

func (c *Challenger) NotifyOfAuth(device data.Device) {

	conn := c.getConnection(device.Address)
	if conn == nil {
		return
	}

	info, err := c.createInfoDTO(device.Address)
	if err != nil {
		log.Printf("failed to get state update for device %q, err: %s", device.Address, err)
		c.Disconnect(device.Address, "Failed to create dto", true)
		return
	}

	challenge, err := device.GetSensitiveChallenge()
	if err != nil {
		log.Printf("failed to get challenge %q, err: %s", device.Address, err)
		c.Disconnect(device.Address, "Failed to get challenge from device", true)
		return
	}

	// The reason we dont use device.Challenge directly here is because it is taken from the event stream and Challenge is redacted :)
	err = SendNotifyAuth(conn, challenge, info, device.Authorised, writeWait)
	if err != nil {
		c.Disconnect(device.Address, "Failed to write", true)
		return
	}

}

func (c *Challenger) UpdateState(address string) {

	conn := c.getConnection(address)
	if conn == nil {
		return
	}

	info, err := c.createInfoDTO(address)
	if err != nil {
		log.Printf("failed to get state update for device %q, err: %s", address, err)
		c.Disconnect(address, "Failed to create dto", true)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		log.Printf("failed to write state to %s, err: %s", address, err)
		c.Disconnect(address, "Failed to write", true)
		return
	}
}

func (c *Challenger) Disconnect(address, reason string, force bool) {
	conn := c.getConnection(address)
	if conn == nil {
		return
	}

	c.Lock()
	delete(c.connections, address)
	c.Unlock()

	if !force {
		conn.Close(websocket.StatusNormalClosure, reason)
		return
	}

	conn.CloseNow()
}

func (c *Challenger) WS(w http.ResponseWriter, r *http.Request) {

	if c.closing {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	clientTunnelIp := utils.GetIPFromRequest(r)

	user := users.GetUserFromContext(r.Context())

	domain, err := data.GetTunnelDomainUrl()
	if err != nil {
		log.Println("was unable to get the wag domain: ", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{domain},
	})
	if err != nil {
		log.Println("failed to accept websocket connection: ", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer func() {
		// close now doesnt wait
		if conn != nil {
			conn.CloseNow()
		}

		c.Lock()
		// Check to make sure the entry we remove from the map is our entry and not some random entry
		if entry, ok := c.connections[clientTunnelIp.String()]; ok && entry == conn {
			delete(c.connections, clientTunnelIp.String())
		}
		c.Unlock()

	}()

	conn.SetReadLimit(maxMessageSize)

	c.Lock()
	prev, ok := c.connections[clientTunnelIp.String()]
	c.connections[clientTunnelIp.String()] = conn
	c.Unlock()

	// This looks a bit funky, but effectively, .Close here can wait for up to 5s for the client to respond.
	// If we lock for 5 seconds we cant accept any clients for that duration which isnt great
	if ok && prev != nil {
		prev.Close(websocket.StatusAbnormalClosure, "Duplicate connection")
		log.Println("Duplicate connection, closing previous")
	}

	log.Println(user.Username, clientTunnelIp, "established new challenge connection!")

	info, err := c.createInfoDTO(clientTunnelIp.String())
	if err != nil {
		log.Println("failed to create initial state. Err ", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		log.Println("Failed to write initial data to client, closing connection. Err", err)
		return
	}

	err = c.Challenge(user.Username, clientTunnelIp.String())
	if err != nil {
		return
	}

	for {

		err := Ping(conn, readWait)
		if err != nil {
			return
		}

		time.Sleep(readWait)
	}

}
