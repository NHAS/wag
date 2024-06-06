package authenticators

import (
	"crypto/subtle"
	"errors"
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

type Challenger struct {
	sync.RWMutex
	listenerKey string
	challenges  map[string]*websocket.Conn

	upgrader websocket.Upgrader
}

func NewChallenger() *Challenger {
	r := &Challenger{
		challenges: make(map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				domain, err := data.GetDomain()
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

func (c *Challenger) Start() error {
	c.Lock()
	defer c.Unlock()

	key, err := data.RegisterEventListener(data.DevicesPrefix, true, c.deviceChangeHandler)
	if err != nil {
		return fmt.Errorf("unable to register device change listener for challenger: %s", err)
	}
	c.listenerKey = key

	return err
}

func (c *Challenger) Stop() error {
	c.Lock()
	defer c.Unlock()

	var errs []error
	if c.listenerKey != "" {
		err := data.DeregisterEventListener(c.listenerKey)
		if err != nil {
			errs = append(errs, err)
		}
	}

	c.listenerKey = ""

	for i := range c.challenges {
		if c.challenges[i] != nil {
			c.challenges[i].Close()
		}
	}

	clear(c.challenges)

	return errors.Join(errs...)
}

func (c *Challenger) deviceChangeHandler(_ string, current, previous data.Device, et data.EventType) error {

	switch et {
	case data.MODIFIED:
		c.Lock()
		defer c.Unlock()

		conn, ok := c.challenges[current.Address]
		if !ok {
			// we dont have a challenge for this device
			return nil
		}

		if current.Challenge != previous.Challenge ||
			current.Endpoint.String() != previous.Endpoint.String() {

			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			err := conn.WriteJSON(struct{ Type string }{Type: "check"})
			if err != nil {
				conn.Close()
				log.Println("failed to check authorisation: ", err)
				return nil
			}
			conn.SetWriteDeadline(time.Time{})

		}

	case data.DELETED:
		c.Lock()
		defer c.Unlock()

		conn, ok := c.challenges[current.Address]
		if !ok {
			// we dont have a challenge for this device
			return nil
		}

		conn.Close()

		delete(c.challenges, current.Address)

	}

	return nil
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
	conn, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(user.Username, remoteAddress, "failed to create websocket challenger:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	c.Lock()
	if conn, ok := c.challenges[remoteAddress.String()]; ok && conn != nil {
		conn.Close()
		delete(c.challenges, remoteAddress.String())
	}
	c.challenges[remoteAddress.String()] = conn
	c.Unlock()

	var response struct {
		Challenge string
	}

	defer func() {
		c.Lock()
		defer c.Unlock()

		conn.Close()
		delete(c.challenges, remoteAddress.String())
	}()

	for {

		err := conn.ReadJSON(&response)
		if err != nil {
			return
		}

		d, err := data.GetDeviceByAddress(remoteAddress.String())
		if err != nil {
			return
		}

		if subtle.ConstantTimeCompare([]byte(d.Challenge), []byte(response.Challenge)) == 1 {
			_, err := data.AuthoriseDevice(user.Username, remoteAddress.String())
			if err != nil {
				log.Println("unable to authorise device based on challenge: ", err)
				return
			}
		} else {
			data.DeauthenticateDevice(remoteAddress.String())
			return
		}
	}

}
