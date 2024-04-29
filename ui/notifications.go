package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/gorilla/websocket"
	"golang.org/x/exp/maps"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Acknowledgement struct {
	Type string
	ID   string
}

func notificationsWS(notifications <-chan Notification) func(w http.ResponseWriter, r *http.Request) {

	var mapLck sync.RWMutex
	servingConnections := map[string]chan<- Notification{}

	go func() {

		for notification := range notifications {

			notificationsMapLck.Lock()
			// If we've already sent a notifcation about it, dont send another
			if _, ok := notificationsMap[notification.ID]; ok {
				notificationsMapLck.Unlock()
				continue
			}
			notificationsMap[notification.ID] = notification
			notificationsMapLck.Unlock()

			for key := range servingConnections {
				go func(key string, notification Notification) {
					servingConnections[key] <- notification
				}(key, notification)
			}
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTP connection to WebSocket connection
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}

		connectionChan := make(chan Notification)
		defer func() {
			mapLck.Lock()
			delete(servingConnections, r.RemoteAddr)
			mapLck.Unlock()

			close(connectionChan)
			conn.Close()
		}()

		mapLck.Lock()
		servingConnections[r.RemoteAddr] = connectionChan
		mapLck.Unlock()

		for notf := range connectionChan {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

			err := conn.WriteJSON(notf)
			if err != nil {
				return
			}

			conn.SetWriteDeadline(time.Time{})
		}

	}
}

type githubResponse struct {
	Body       string
	Prerelease bool   `json:"prerelease"`
	TagName    string `json:"tag_name"`
	Published  string `json:"published_at"`
	Url        string `json:"html_url"`
}

type Notification struct {
	ID         string
	Heading    string
	Message    []string
	Url        string
	Time       time.Time
	Color      string
	OpenNewTab bool
}

var (
	notificationsMapLck sync.RWMutex
	notificationsMap    = map[string]Notification{}
)

func getNotifications() []Notification {

	notificationsMapLck.RLock()
	notfs := maps.Values(notificationsMap)
	notificationsMapLck.RUnlock()

	sort.Slice(notfs, func(i, j int) bool {
		return notfs[i].Time.After(notfs[j].Time)
	})

	return notfs
}

func startUpdateChecker(notifications chan<- Notification) {
	go func() {

		for {
			resp, err := http.Get("https://api.github.com/repos/NHAS/wag/releases/latest")
			if err != nil {
				log.Println("unable to fetch updates: ", err)
				return
			}
			defer resp.Body.Close()

			var gr githubResponse
			err = json.NewDecoder(resp.Body).Decode(&gr)
			if err != nil {
				log.Println("unable to parse update json: ", err)
				return
			}

			notifications <- Notification{
				Heading:    gr.TagName,
				Message:    strings.Split(gr.Body, "\r\n"),
				Url:        gr.Url,
				Time:       time.Now(),
				OpenNewTab: true,
				Color:      "#0bb329",
			}

			<-time.After(15 * time.Minute)
		}
	}()
}

func receiveErrorNotifications(notifications chan<- Notification) func(key string, current, previous data.EventError, et data.EventType) error {

	return func(key string, current, previous data.EventError, et data.EventType) error {
		switch et {
		case data.CREATED:

			msg := Notification{
				ID:         current.ErrorID,
				Heading:    "Node Error",
				Message:    []string{"Node " + current.NodeID, current.Error},
				Url:        "/cluster/events/",
				Time:       time.Now(),
				OpenNewTab: false,
				Color:      "#db0b3c",
			}

			notifications <- msg
		case data.DELETED:

			notificationsMapLck.Lock()
			delete(notificationsMap, previous.ErrorID)
			notificationsMapLck.Unlock()
		}
		return nil
	}
}

func monitorNumberOfClusterMembers(notifications chan<- Notification) {
	for {
		if len(data.GetMembers()) == 2 {
			notifications <- Notification{
				ID:      "monitor_node_number",
				Heading: "Unsafe Cluster Size!",
				Message: []string{"A wag cluster of two nodes doubles the risk of cluster failure.",
					"If either node fails the whole cluster will become unrecoverable.",
					"It is recommended to add another node."},
				Url:        "/cluster/members",
				Time:       time.Now(),
				OpenNewTab: false,
				Color:      "#db0b3c",
			}

		}
		time.Sleep(30 * time.Second)
	}
}
