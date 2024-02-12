package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/data"
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

func notificationsWS(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	go func() {

	}()

}

type githubResponse struct {
	Body       string
	Prerelease bool   `json:"prerelease"`
	TagName    string `json:"tag_name"`
	Published  string `json:"published_at"`
	Url        string `json:"html_url"`
}

type Notification struct {
	ID      string
	Heading string
	Message []string
	Url     string
}

var (
	mostRecentUpdate *Notification
	lastChecked      time.Time
)

func getUpdate() Notification {

	should, err := data.ShouldCheckUpdates()
	if err != nil || !should {
		return Notification{}
	}

	if time.Now().After(lastChecked.Add(15*time.Minute)) || mostRecentUpdate == nil {
		resp, err := http.Get("https://api.github.com/repos/NHAS/wag/releases/latest")
		if err != nil {
			return Notification{}
		}
		defer resp.Body.Close()

		var gr githubResponse
		err = json.NewDecoder(resp.Body).Decode(&gr)
		if err != nil {
			return Notification{}
		}

		mostRecentUpdate = &Notification{
			Heading: gr.TagName,
			Message: strings.Split(gr.Body, "\r\n"),
			Url:     gr.Url,
		}
	}

	return *mostRecentUpdate
}
