package adminui

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/data/watcher"
	"github.com/NHAS/wag/pkg/safedecoder"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func (au *AdminUI) webhookWebSocket(w http.ResponseWriter, r *http.Request) {
	config, err := au.db.GetWebserverConfig(data.Public)
	if err != nil {
		log.Printf("failed to get web server config for public server: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	conn, err := websocket.Accept(w, r, nil)
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
	}()

	id, err := au.db.CreateTempWebhook()
	if err != nil {
		log.Printf("unable to create temporary webhook: %s", err)
		return

	}

	var url WebhookInputUrlDTO
	url.Type = "URL"

	host, port, _ := net.SplitHostPort(config.ListenAddress)

	if config.Domain != "" {
		host = config.Domain
	}

	if host == "" {
		host = "127.0.0.1"
	}

	scheme := "http"
	if config.TLS {
		scheme = "https"
	}

	url.Url = fmt.Sprintf("%s://%s:%s/webhooks/%s", scheme, host, port, id)
	url.ID = id

	err = wsjson.Write(context.Background(), conn, url)
	if err != nil {
		return
	}

	var lastRequestWatcher *watcher.Watcher[string]

	onDelete := func(_ string, current, previous string) error {
		if lastRequestWatcher != nil {
			lastRequestWatcher.Close()
		}

		return nil
	}

	onUpdate := func(key string, current, previous string) error {

		var c map[string]any

		err := json.Unmarshal([]byte(current), &c)
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = wsjson.Write(ctx, conn, WebhookInputAttributesDTO{
				Type:  "attributes",
				Error: err.Error(),
			})
			cancel()

			if err != nil {
				log.Println("failed to write to websocket: ", err)
				lastRequestWatcher.Close()
			}

			return nil
		}

		result := data.Unpack("", c)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = wsjson.Write(ctx, conn, WebhookInputAttributesDTO{
			Type:       "attributes",
			Attributes: result,
			Error:      "",
		})
		cancel()

		if err != nil {
			log.Println("failed to write to websocket: ", err)
			lastRequestWatcher.Close()
		}

		return nil
	}

	// setup database watch on key to see if there is any data/json coming in from the webhook

	lastRequestWatcher, err = watcher.Watch(au.db, au.db.GetLastWebhookRequestPath(data.TempWebhooksPrefix, id), false,
		watcher.OnCreate(onUpdate),
		watcher.OnModification(onUpdate),

		watcher.OnDelete(onDelete),
	)
	if err != nil {
		log.Println("failed to start watcher on temporary webhook: ", err)
		return
	}

	lastRequestWatcher.Wait()
}

func (au *AdminUI) getWebhooks(w http.ResponseWriter, r *http.Request) {

	hooks, err := au.db.GetWebhooks()
	if err != nil {
		log.Printf("failed to get all webhook err: %s", err)

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hooks)

}

func (au *AdminUI) createWebhook(w http.ResponseWriter, r *http.Request) {
	var (
		webhook data.WebhookDTO
		err     error
	)

	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&webhook)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.db.CreateWebhook(webhook)
	if err != nil {
		log.Printf("failed to create webhook: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

}

func (au *AdminUI) deleteWebhooks(w http.ResponseWriter, r *http.Request) {
	var (
		webhooks []string
		err      error
	)

	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&webhooks)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.db.DeleteWebhooks(webhooks)
	if err != nil {
		log.Printf("failed to delete webhook: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}
