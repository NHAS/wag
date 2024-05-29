package server

import (
	"encoding/json"
	"net/http"

	"github.com/NHAS/wag/internal/data"
)

func listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := data.GetGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(groups)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
