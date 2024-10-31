package data

import (
	"net"
	"testing"
)

func TestHostIPWithMask(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{
			name:     "IPv4 address",
			ip:       net.ParseIP("192.168.1.1"),
			expected: "192.168.1.1/32",
		},
		{
			name:     "IPv6 address",
			ip:       net.ParseIP("2001:db8::1"),
			expected: "2001:db8::1/128",
		},
		{
			name:     "IPv4 loopback",
			ip:       net.ParseIP("127.0.0.1"),
			expected: "127.0.0.1/32",
		},
		{
			name:     "IPv6 loopback",
			ip:       net.ParseIP("::1"),
			expected: "::1/128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostIPWithMask(tt.ip); got != tt.expected {
				t.Errorf("hostIPWithMask() = %v, want %v", got, tt.expected)
			}
		})
	}

	// Test with nil IP
	t.Run("nil IP", func(t *testing.T) {
		var nilIP net.IP
		got := hostIPWithMask(nilIP)
		if got != "<nil>/32" {
			t.Errorf("hostIPWithMask() with nil IP = %v, want <nil>/32", got)
		}
	})
}
