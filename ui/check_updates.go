package ui

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

type githubResponse struct {
	Body       string
	Prerelease bool   `json:"prerelease"`
	TagName    string `json:"tag_name"`
	Published  string `json:"published_at"`
	Url        string `json:"html_url"`
}

type Update struct {
	New           bool
	UpdateVersion string
	UpdateMessage []string
	Url           string
	Released      string
}

var (
	mostRecentUpdate *Update
	lastChecked      time.Time
)

func getUpdate() Update {

	should, err := data.CheckUpdates()
	if err != nil || !should {
		return Update{}
	}

	if time.Now().After(lastChecked.Add(15*time.Minute)) || mostRecentUpdate == nil {
		resp, err := http.Get("https://api.github.com/repos/NHAS/wag/releases/latest")
		if err != nil {
			return Update{}
		}
		defer resp.Body.Close()

		var gr githubResponse
		err = json.NewDecoder(resp.Body).Decode(&gr)
		if err != nil {
			return Update{}
		}

		mostRecentUpdate = &Update{
			UpdateVersion: gr.TagName,
			UpdateMessage: strings.Split(gr.Body, "\r\n"),
			Url:           gr.Url,
			Released:      gr.Published,
		}
	}

	mostRecentUpdate.New = strings.Split(config.Version, "-")[0] != mostRecentUpdate.UpdateVersion

	return *mostRecentUpdate
}
