package adminui

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/safedecoder"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Acknowledgement struct {
	Type string
	ID   string
}

func (au *AdminUI) notificationsWS(notifications <-chan NotificationDTO) func(w http.ResponseWriter, r *http.Request) {

	var mapLck sync.RWMutex
	servingConnections := map[string]chan<- NotificationDTO{}

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
				go func(key string, notification NotificationDTO) {
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

		connectionChan := make(chan NotificationDTO)
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
			err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				return
			}

			err = conn.WriteJSON(notf)
			if err != nil {
				return
			}

			err = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
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

var (
	notificationsMapLck sync.RWMutex
	notificationsMap    = map[string]NotificationDTO{}
)

func (au *AdminUI) startUpdateChecker(notifications chan<- NotificationDTO) {
	go func() {

		for {
			resp, err := http.Get("https://api.github.com/repos/NHAS/wag/releases/latest")
			if err != nil {
				log.Println("unable to fetch updates: ", err)
				return
			}

			var gr githubResponse
			err = safedecoder.Decoder(resp.Body).Decode(&gr)
			resp.Body.Close()
			if err != nil {
				log.Println("unable to parse update json: ", err)
				return
			}

			notifications <- NotificationDTO{
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

func (au *AdminUI) receiveErrorNotifications(notifications chan<- NotificationDTO) func(key string, et data.EventType, current, previous data.EventError) error {

	return func(key string, et data.EventType, current, previous data.EventError) error {
		switch et {
		case data.CREATED:

			msg := NotificationDTO{
				ID:         current.ErrorID,
				Heading:    "Node Error",
				Message:    []string{"Node " + current.NodeID, current.Error},
				Url:        "/cluster/events/",
				Time:       current.Time,
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

func (au *AdminUI) monitorClusterMembers(notifications chan<- NotificationDTO) {
	for {
		currentMembers, err := au.ctrl.GetClusterMembers()
		if err != nil {
			log.Println("unable to get cluster members, err: ", err)
		} else {

			if len(currentMembers) == 2 {
				notifications <- NotificationDTO{
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

			} else {
				notificationsMapLck.Lock()
				delete(notificationsMap, "monitor_node_number")
				notificationsMapLck.Unlock()
			}

			for i := range currentMembers {

				lastPing, err := au.ctrl.GetClusterMemberLastPing(currentMembers[i].ID.String())
				if err != nil {
					continue
				}

				if lastPing.Before(time.Now().Add(-14 * time.Second)) {

					notificationsMapLck.Lock()
					delete(notificationsMap, "node_degrading_"+currentMembers[i].ID.String())
					notificationsMapLck.Unlock()

					notifications <- NotificationDTO{
						ID:         "node_dead_" + currentMembers[i].ID.String(),
						Heading:    "Node " + currentMembers[i].ID.String() + " dead",
						Message:    []string{currentMembers[i].ID.String() + " has not sent ping in 15 seconds and is assumed dead"},
						Url:        "/cluster/members",
						Time:       time.Now(),
						OpenNewTab: false,
						Color:      "#db0b3c",
					}

				} else if lastPing.Before(time.Now().Add(-6 * time.Second)) {
					notifications <- NotificationDTO{
						ID:         "node_degrading_" + currentMembers[i].ID.String(),
						Heading:    "Node " + currentMembers[i].ID.String() + " degraded",
						Message:    []string{currentMembers[i].ID.String() + " has exceeded expected liveness ping (5 seconds)"},
						Url:        "/cluster/members",
						Time:       time.Now(),
						OpenNewTab: false,
						Color:      "#ff5f15",
					}

				} else {
					// Node is alive
					notificationsMapLck.Lock()
					delete(notificationsMap, "node_degrading_"+currentMembers[i].ID.String())
					delete(notificationsMap, "node_dead_"+currentMembers[i].ID.String())
					notificationsMapLck.Unlock()
				}

			}

		}

		time.Sleep(15 * time.Second)
	}
}
