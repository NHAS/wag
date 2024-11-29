package router

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/gorilla/websocket"
)

type wsConnWrapper struct {
	*websocket.Conn
	wait chan interface{}
	sync.Mutex
	isClosed bool
}

func (ws *wsConnWrapper) Await() <-chan interface{} {
	return ws.wait
}

func (ws *wsConnWrapper) Close() error {
	ws.Lock()
	defer ws.Unlock()

	if ws.isClosed {
		return nil
	}

	ws.isClosed = true

	close(ws.wait)
	return ws.Conn.Close()
}

type Challenger struct {
	sync.RWMutex
	connections map[string]*wsConnWrapper

	upgrader websocket.Upgrader
}

func NewChallenger() *Challenger {
	r := &Challenger{
		connections: make(map[string]*wsConnWrapper),
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

	return r
}

func (c *Challenger) Challenge(address string) error {
	c.RLock()
	defer c.RUnlock()

	var err error

	conn, ok := c.connections[address]
	if !ok {
		return fmt.Errorf("no connection found for device: %s", address)
	}

	err = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		conn.Close()
		return err
	}

	err = conn.WriteJSON("challenge")
	if err != nil {
		conn.Close()
		return err
	}

	err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		conn.Close()
		return err
	}

	msg := struct{ Challenge string }{}
	err = conn.ReadJSON(&msg)
	if err != nil {
		conn.Close()
		return err
	}

	deviceDetails, err := data.GetDeviceByAddress(address)
	if err != nil {
		return fmt.Errorf("failed to get device address for ws challenge: %s", err)
	}

	maxLifetimeMinutes, err := data.GetSessionLifetimeMinutes()
	if err != nil {
		return fmt.Errorf("failed max lifetime: %s", err)
	}

	if time.Now().After(deviceDetails.Authorised.Add(time.Duration(maxLifetimeMinutes) * time.Minute)) {
		return fmt.Errorf("challenge came from expired session")
	}

	if subtle.ConstantTimeCompare([]byte(deviceDetails.Challenge), []byte(msg.Challenge)) != 1 {
		return fmt.Errorf("challenge does not match")
	}

	return nil
}

func (c *Challenger) Reset(address string) {
	c.RLock()
	defer c.RUnlock()

	conn, ok := c.connections[address]
	if !ok {
		return
	}

	conn.WriteJSON("reset")
}

func (c *Challenger) WS(w http.ResponseWriter, r *http.Request) {
	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println("unknown", remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Upgrade HTTP connection to WebSocket connection
	_c, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(user.Username, remoteAddress, "failed to create websocket:", err)
		// do not error here as upgrade has already done it
		return
	}

	conn := &wsConnWrapper{Conn: _c, wait: make(chan interface{})}

	defer func() {
		c.Lock()
		if conn != nil {
			conn.Close()
		}
		delete(c.connections, remoteAddress.String())
		c.Unlock()

	}()

	c.Lock()
	if prev, ok := c.connections[remoteAddress.String()]; ok && prev != nil {
		prev.Close()
	}

	c.connections[remoteAddress.String()] = conn
	c.Unlock()

	err = c.Challenge(remoteAddress.String())
	if err != nil {
		c.Reset(remoteAddress.String())
		log.Printf("%s:%s client did not complete inital ws challenge: %s", user.Username, remoteAddress, err)
		return
	}

	log.Println(user.Username, remoteAddress, "established new challenge connection!")

	<-conn.Await()
}
