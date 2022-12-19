package utils

import (
	"net"
	"net/http"
	"strings"

	"github.com/NHAS/wag/config"
)

func GetIP(addr string) string {
	for i := len(addr) - 1; i > 0; i-- {
		if addr[i] == ':' || addr[i] == '/' {
			return addr[:i]
		}
	}
	return addr
}

func GetIPFromRequest(r *http.Request) net.IP {

	//Do not respect the X-Forwarded-For header until we are explictly told we are being proxied.
	if config.Values().Proxied {
		ips := r.Header.Get("X-Forwarded-For")

		addresses := strings.Split(ips, ",")
		if ips != "" && len(addresses) > 0 && net.ParseIP(addresses[0]) != nil {
			return net.ParseIP(addresses[0]).To4()
		}
	}

	return net.ParseIP(GetIP(r.RemoteAddr)).To4()
}
