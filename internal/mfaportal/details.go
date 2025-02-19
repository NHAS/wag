package mfaportal

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/gorilla/websocket"
)

// https://github.com/gorilla/websocket/blob/main/examples/chat/client.go
const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

type Challenger struct {
	sync.RWMutex
	connections map[string]*websocket.Conn
	deviceKey   string
	upgrader    websocket.Upgrader
}

func NewChallenger() (*Challenger, error) {
	r := &Challenger{
		connections: make(map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				domain, err := data.GetTunnelDomainUrl()
				if err != nil {
					log.Println("was unable to get the wag domain: ", err)
					return false
				}

				valid := r.Header.Get("Origin") == domain
				if !valid {
					log.Printf("websocket origin does not equal expected value: %q != %q", r.Header.Get("Origin"), domain)
				}

				return valid
			},
		},
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
		c.Disconnect(current.Address)
	case data.MODIFIED:
		if current.Endpoint.String() != previous.Endpoint.String() {
			if current.ChallengeExists() == nil {
				c.NotifyDeauth(current.Address)
			}
		}
	}
	return nil

}

func (c *Challenger) Close() error {
	c.Lock()
	defer c.Unlock()

	for _, conn := range c.connections {
		conn.SetWriteDeadline(time.Now().Add(writeWait))
		conn.WriteMessage(websocket.CloseMessage, []byte{})
		conn.Close()
	}
	clear(c.connections)

	return data.DeregisterEventListener(c.deviceKey)
}

func (c *Challenger) Disconnect(address string) {
	c.Lock()
	defer c.Unlock()

	conn, ok := c.connections[address]
	if !ok {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(writeWait))
	conn.WriteMessage(websocket.CloseMessage, []byte{})
	conn.Close()
	delete(c.connections, address)
}

func (c *Challenger) NotifyDeauth(address string) {
	c.Lock()
	defer c.Unlock()

	conn, ok := c.connections[address]
	if !ok {
		return
	}

	var d DeauthNotificationDTO
	d.Status = "deauthed"

	conn.WriteJSON(d)
}

func (c *Challenger) WS(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	user := users.GetUserFromContext(r.Context())

	// Upgrade HTTP connection to WebSocket connection
	conn, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to create websocket:", err)
		// do not error here as upgrade has already done it
		return
	}
	conn.SetReadLimit(maxMessageSize)
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })

	defer func() {
		c.Lock()
		if conn != nil {
			conn.Close()
		}
		delete(c.connections, clientTunnelIp.String())
		c.Unlock()

	}()

	c.Lock()
	if prev, ok := c.connections[clientTunnelIp.String()]; ok && prev != nil {
		prev.Close()
	}

	c.connections[clientTunnelIp.String()] = conn
	c.Unlock()

	log.Println(user.Username, clientTunnelIp, "established new challenge connection!")

	authenticators := authenticators.GetAllEnabledMethods()
	names := []MFAMethod{}
	for _, a := range authenticators {
		names = append(names, MFAMethod{
			FriendlyName: a.FriendlyName(),
			Method:       a.Type(),
		})
	}

	info := UserInfoDTO{
		HelpMail:            data.GetHelpMail(),
		AvailableMfaMethods: names,
		Locked:              user.Locked,
		Registered:          user.Enforcing,
		Username:            user.Username,
		Authorised:          Authed(r.Context()),
	}

	conn.SetWriteDeadline(time.Now().Add(writeWait))
	err = conn.WriteJSON(info)
	if err != nil {
		return
	}
	conn.SetWriteDeadline(time.Time{})

	for {
		conn.SetWriteDeadline(time.Now().Add(writeWait))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			return
		}

		time.Sleep(pingPeriod)
	}

}
