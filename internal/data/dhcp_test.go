package data

import (
	"log"
	"net"
	"testing"
)

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		inc      uint
		expected string
	}{
		// IPv4 tests
		{
			name:     "IPv4 increment by 1",
			ip:       "192.168.1.1",
			inc:      1,
			expected: "192.168.1.2",
		},
		{
			name:     "IPv4 increment by 255",
			ip:       "192.168.1.1",
			inc:      255,
			expected: "192.168.2.0",
		},
		{
			name:     "IPv4 crosses multiple octets",
			ip:       "192.168.255.255",
			inc:      1,
			expected: "192.169.0.0",
		},
		// IPv6 tests
		{
			name:     "IPv6 increment by 1",
			ip:       "2001:db8::1",
			inc:      1,
			expected: "2001:db8::2",
		},
		{
			name:     "IPv6 increment by 255",
			ip:       "2001:db8::1",
			inc:      255,
			expected: "2001:db8::100",
		},
		{
			name:     "IPv6 increment across boundary",
			ip:       "2001:db8::ffff",
			inc:      1,
			expected: "2001:db8::1:0",
		},
		{
			name:     "IPv6 increment zero address",
			ip:       "::",
			inc:      1,
			expected: "::1",
		},
		{
			name:     "IPv6 increment large number",
			ip:       "2001:db8::",
			inc:      65535,
			expected: "2001:db8::ffff",
		},
		{
			name:     "IPv6 with zeros in middle",
			ip:       "2001:db8:0:0:0:0:0:1",
			inc:      1,
			expected: "2001:db8::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			result := incrementIP(ip, tt.inc)
			if result.String() != tt.expected {

				log.Println(len(ip), len(result))

				t.Errorf("incrementIP(%s, %d) = %s; want %s",
					tt.ip, tt.inc, result.String(), tt.expected)
			}
		})
	}
}

func TestIncrementIPOverflow(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		inc  uint
	}{
		{
			name: "IPv4 overflow max IP",
			ip:   "255.255.255.255",
			inc:  1,
		},
		{
			name: "IPv6 overflow max IP",
			ip:   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			inc:  1,
		},
		{
			name: "IPv6 large overflow",
			ip:   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00",
			inc:  256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("incrementIP(%s, %d) paniced",
						tt.ip, tt.inc)
				}
			}()

			incrementIP(ip, tt.inc)
		})
	}
}

func TestChooseInitial(t *testing.T) {

	_, cidr, err := net.ParseCIDR("192.168.3.4/24")
	if err != nil {
		t.Fatal(err)
	}

	addr, err := chooseInitalIP(cidr)
	if err != nil {
		t.Fatal(err)
	}

	if !cidr.Contains(addr) {
		t.Fatalf("does not contain address, %s", addr)
	}

	_, cidr, err = net.ParseCIDR("2001:db8:abcd:1234:c000::/66")
	if err != nil {
		t.Fatal(err)
	}

	addr, err = chooseInitalIP(cidr)
	if err != nil {
		t.Fatal(err)
	}

	if !cidr.Contains(addr) {
		t.Fatalf("does not contain address, %s", addr)
	}
}
