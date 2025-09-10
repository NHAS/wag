package debug

import (
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/NHAS/wag/internal/config"
)

func StartPprof() {
	go func() {
		if config.Values.DevMode {
			log.Println("debug pprof server")
			log.Println(http.ListenAndServe(":6060", nil))
		}
	}()
}
