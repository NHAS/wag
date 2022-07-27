package utils

import (
	"crypto/rand"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
)

func Check(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func GetIP(addr string) string {
	for i := len(addr) - 1; i > 0; i-- {
		if addr[i] == ':' || addr[i] == '/' {
			return addr[:i]
		}
	}
	return addr
}

func GetIPFromRequest(r *http.Request) string {
	ips := r.Header.Get("X-Forwarded-For")

	addresses := strings.Split(ips, ",")
	if ips != "" && len(addresses) > 0 && net.ParseIP(addresses[0]) != nil {
		return addresses[0]
	}

	return GetIP(r.RemoteAddr)
}

func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func IncrementIP(origIP, cidr string) (string, error) {
	ip := net.ParseIP(origIP)
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return origIP, err
	}
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	if !ipNet.Contains(ip) {
		return origIP, errors.New("overflowed CIDR while incrementing IP")
	}
	return ip.String(), nil
}
