package debug

import (
	"net/http"
	_ "net/http/pprof"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/config"
)

func StartPprof() {
	go func() {
		if config.Values.DevMode {
			log.Info().Msg("debug pprof server started on :6060")

			http.ListenAndServe(":6060", nil)
		}
	}()
}
