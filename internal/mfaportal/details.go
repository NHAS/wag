package mfaportal

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
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
	deviceKey   string
}

func NewChallenger() (*Challenger, error) {
	r := &Challenger{
		connections: make(map[string]*websocket.Conn),
	}

	var err error
	r.deviceKey, err = data.RegisterEventListener(data.DevicesPrefix, true, r.deviceChanges)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (c *Challenger) deviceChanges(_ string, current, previous data.Device, et data.EventType) error {

	switch et {
	case data.DELETED:
		c.Disconnect(current.Address, "Device deleted.")
	case data.MODIFIED:
		if current.Endpoint.String() != previous.Endpoint.String() {
			if current.ChallengeExists() == nil {
				c.NotifyDeauth(current.Address)
			} else {
				c.Challenge(current.Username, current.Address)
			}
		}

		if data.HasDeviceAuthorised(current, previous) {
			log.Println("device authorised, sending update")
			c.NotifyOfAuth(current)
		}
	}
	return nil

}

func (c *Challenger) Close() error {
	c.Lock()
	defer c.Unlock()
	c.closing = true

	for _, conn := range c.connections {
		conn.Close(websocket.StatusGoingAway, "Going away")
	}
	clear(c.connections)

	return data.DeregisterEventListener(c.deviceKey)
}

func (c *Challenger) Challenge(username, address string) {
	c.Lock()
	defer c.Unlock()

	conn, ok := c.connections[address]
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err := wsjson.Write(ctx, conn, Challenge())
	cancel()
	if err != nil {
		c.disconnect(address, "Bad connection")
		return
	}

	var potentialChallenge ChallengeResponseDTO
	ctx, cancel = context.WithTimeout(context.Background(), readWait)
	err = wsjson.Read(ctx, conn, &potentialChallenge)
	cancel()
	if err != nil {
		c.disconnect(address, "No challenge response")
		return
	}

	if potentialChallenge.Challenge != "" {

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

func (c *Challenger) NotifyOfAuth(device data.Device) {
	c.Lock()
	defer c.Unlock()

	conn, ok := c.connections[device.Address]
	if !ok {
		log.Println("device not found: ", device.Address, c.connections)
		return
	}

	user, err := users.GetUser(device.Username)
	if err != nil {
		log.Println("failed to get user object from device: ", err)
		c.disconnect(device.Address, "Bad user")
		return
	}

	defaultMFAMethod, err := data.GetDefaultMfaMethod()
	if err != nil {
		log.Println("failed to get default MFA method for updating client: ", err)
		return
	}

	lockout, err := data.GetLockout()
	if err != nil {
		log.Println("failed to get lockout for updating client: ", err)
		return
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
		Username:            device.Username,
		Authorised:          true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		conn.CloseNow()
		delete(c.connections, device.Address)
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

func (c *Challenger) NotifyDeauth(address string) {
	c.Lock()
	defer c.Unlock()

	conn, ok := c.connections[address]
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err := wsjson.Write(ctx, conn, Deauth())
	cancel()
	if err != nil {
		conn.CloseNow()
		delete(c.connections, address)
		return
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

func (c *Challenger) WS(w http.ResponseWriter, r *http.Request) {

	if c.closing {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	clientTunnelIp := utils.GetIPFromRequest(r)

	user := users.GetUserFromContext(r.Context())

	device, err := data.GetDeviceByAddress(clientTunnelIp.String())
	if err != nil {
		log.Println("failed to get device: ", err)
		return
	}

	defaultMFAMethod, err := data.GetDefaultMfaMethod()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)

		return
	}

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

	lockout, err := data.GetLockout()
	if err != nil {
		log.Println("failed to get lockout for updating client: ", err)
		return
	}

	info := UserInfoDTO{
		Type:                Init,
		UserMFAMethod:       user.GetMFAType(),
		HelpMail:            data.GetHelpMail(),
		DefaultMFAMethod:    defaultMFAMethod,
		AvailableMfaMethods: c.getMfaMethods(),
		AccountLocked:       user.Locked,
		DeviceLocked:        device.Attempts > lockout,
		Registered:          user.Enforcing,
		Username:            user.Username,
		Authorised:          Authed(r.Context()),
	}

	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	err = wsjson.Write(ctx, conn, info)
	cancel()
	if err != nil {
		log.Println("Failed to write initial data to client, closing connection. Err", err)
		return
	}

	var potentialChallenge ChallengeResponseDTO
	ctx, cancel = context.WithTimeout(context.Background(), readWait)
	err = wsjson.Read(ctx, conn, &potentialChallenge)
	cancel()
	if err != nil {
		log.Println("Failed to read inital challenge")
		return
	}

	if potentialChallenge.Challenge != "" {

		err = data.ValidateChallenge(user.Username, clientTunnelIp.String(), potentialChallenge.Challenge)
		if err != nil {
			log.Println("client failed challenge: ", err)
		} else {
			err = data.AuthoriseDevice(info.Username, clientTunnelIp.String())
			if err != nil {
				log.Println("User device had correct challenge, but cluster failed to authorise: ", err)
			}
		}
	}

	for {
		ctx, cancel = context.WithTimeout(context.Background(), writeWait)
		err := wsjson.Write(ctx, conn, Ping())
		cancel()
		if err != nil {
			return
		}

		ctx, cancel = context.WithTimeout(context.Background(), readWait)
		var res PingResponseDTO
		err = wsjson.Read(ctx, conn, &res)
		cancel()
		if err != nil {
			return
		}

		time.Sleep(readWait)
	}

}
