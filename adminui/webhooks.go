package adminui

import (
	"log"
	"net/http"

	"github.com/coder/websocket"
)

func (au *AdminUI) webhookWebSocket(w http.ResponseWriter, r *http.Request) {
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

	// make temporary webhook location in db

	// setup database watch on key to see if there is any data/json coming in from the webhook

}

func (au *AdminUI) getWebhooks(w http.ResponseWriter, r *http.Request) {
}

func (au *AdminUI) createWebhook(w http.ResponseWriter, r *http.Request) {
	// delete existing temporary webhook

}

func (au *AdminUI) deleteWebhook(w http.ResponseWriter, r *http.Request) {

}
