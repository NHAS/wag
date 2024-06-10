package utils

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/config"
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
	if config.Values.NumberProxies > 0 {
		ips := r.Header.Get("X-Forwarded-For")
		addresses := strings.Split(ips, ",")

		if ips != "" && len(addresses) > 0 {

			if len(addresses)-config.Values.NumberProxies < 0 {
				log.Println("WARNING XFF parsing may be broken: ", len(addresses)-config.Values.NumberProxies, " check config.Values.NumberProxies")
				return net.ParseIP(strings.TrimSpace(addresses[len(addresses)-1])).To4()
			}

			return net.ParseIP(strings.TrimSpace(addresses[len(addresses)-config.Values.NumberProxies])).To4()
		}
	}

	return net.ParseIP(GetIP(r.RemoteAddr)).To4()
}

func GenerateRandomHex(n uint32) (string, error) {
	b, err := GenerateRandom(n)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func GenerateRandom(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return b, err
	}

	return b, nil
}
