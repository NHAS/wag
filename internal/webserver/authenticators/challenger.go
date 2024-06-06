package authenticators

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/gorilla/websocket"
)

type challenge struct {
	ws    *websocket.Conn
	value string
}

type Challenger struct {
	sync.RWMutex
	listenerKey string
	challenges  map[string]challenge
}

func NewChallenger() *Challenger {
	r := &Challenger{
		challenges: make(map[string]challenge),
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
		if c.challenges[i].ws != nil {
			c.challenges[i].ws.Close()
		}
	}

	clear(c.challenges)

	return errors.Join(errs...)
}

func (c *Challenger) IssueChallengeToken(w http.ResponseWriter, r *http.Request) {
	c.Lock()
	defer c.Unlock()

	cookie := http.Cookie{
		Name:     "challenge",
		Value:    "abcd",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   r.URL.Scheme == "https",
		HttpOnly: false,
	}
	http.SetCookie(w, &cookie)
}

func (c *Challenger) deviceChangeHandler(_ string, current, previous data.Device, et data.EventType) error {
	return nil
}
