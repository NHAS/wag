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

	return r, nil
}

func (c *Challenger) Close() error {
	c.Lock()
	defer c.Unlock()
	c.closing = true

	for _, conn := range c.connections {
		conn.Close(websocket.StatusGoingAway, "Going away")
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

func (c *Challenger) deviceChanges(_ string, current, previous data.Device, et data.EventType) error {

	lockout, err := data.GetLockout()
	if err != nil {
		return fmt.Errorf("cannot get lockout: %s", err)
	}

	switch et {
	case data.DELETED:
		c.Disconnect(current.Address, "Device deleted.")
	case data.MODIFIED:
		if current.Endpoint.String() != previous.Endpoint.String() {
			if err := current.ChallengeExists(); err != nil {
				c.UpdateState(current)

			} else {
				c.Challenge(current.Username, current.Address)
			}
		}

		if current.Attempts > lockout || // If the number of authentication attempts on a device has exceeded the max
			current.Authorised.IsZero() { // If we've explicitly deauthorised a device
			c.UpdateState(current)
		}

		// give a notification when an device is unlocked as well
		if current.Attempts < lockout {
			c.UpdateState(current)
		}

		if data.HasDeviceAuthorised(current, previous) {
			c.NotifyOfAuth(current)
		}
	}
	return nil

}

func (c *Challenger) Challenge(username, address string) {

	conn := c.getConnection(address)
	if conn == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err := wsjson.Write(ctx, conn, Challenge())
	cancel()
	if err != nil {
		c.Disconnect(address, "Bad connection")
		return
	}

	potentialChallenge, err := ReadChallenge(conn, readWait)
	if err != nil {
		c.Disconnect(address, "No challenge response")
		return
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

func (c *Challenger) NotifyOfAuth(challenge data.Device) {

	conn := c.getConnection(challenge.Address)
	if conn == nil {
		return
	}

	info, err := c.createInfoDTO(challenge.Address)
	if err != nil {
		log.Printf("failed to get state update for device %q, err: %s", challenge.Address, err)
		conn.CloseNow()
		delete(c.connections, challenge.Address)
		return
	}

	err = SendNotifyAuth(conn, challenge.Challenge, info, writeWait)
	if err != nil {
		conn.CloseNow()
		delete(c.connections, challenge.Address)
		return
	}

}

func (c *Challenger) UpdateState(d data.Device) {

	conn := c.getConnection(d.Address)
	if conn == nil {
		return
	}

	info, err := c.createInfoDTO(d.Address)
	if err != nil {
		log.Printf("failed to get state update for device %q, err: %s", d.Address, err)
		conn.CloseNow()
		delete(c.connections, d.Address)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		log.Printf("failed to write state to %s, err: %s", d.Address, err)
		return
	}
}

func (c *Challenger) Disconnect(address, reason string) {
	c.Lock()
	defer c.Unlock()

	c.disconnect(address, reason)
}

func (c *Challenger) disconnect(address, reason string) {
	conn, ok := c.connections[address]
	if !ok {
		return
	}
	conn.Close(websocket.StatusNormalClosure, reason)
	delete(c.connections, address)
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
	defer conn.CloseNow()

	conn.SetReadLimit(maxMessageSize)

	defer func() {
		c.Lock()
		if conn != nil {
			conn.CloseNow()
		}

		// Check to make sure the entry we remove from the map is our entry and not some random entry
		if entry, ok := c.connections[clientTunnelIp.String()]; ok && entry == conn {
			delete(c.connections, clientTunnelIp.String())
		}
		c.Unlock()

	}()

	c.Lock()
	if prev, ok := c.connections[clientTunnelIp.String()]; ok && prev != nil {
		prev.Close(websocket.StatusAbnormalClosure, "Duplicate connection")
		log.Println("Duplicate connection, closing previous")
	}

	c.connections[clientTunnelIp.String()] = conn
	c.Unlock()

	log.Println(user.Username, clientTunnelIp, "established new challenge connection!")

	info, err := c.createInfoDTO(clientTunnelIp.String())
	if err != nil {
		log.Println("failed to create initial state")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		log.Println("Failed to write initial data to client, closing connection. Err", err)
		return
	}

	c.Challenge(user.Username, clientTunnelIp.String())

	for {

		err := Ping(conn, readWait)
		if err != nil {
			log.Println("failed to ping", err)
			return
		}

		time.Sleep(readWait)
	}

}
