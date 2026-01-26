package data

import "testing"

func TestDomainToUrl(t *testing.T) {

	expected := "http://vpn.test:8888"
	if url, err := webserverUrl("vpn.test", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:8080"
	if url, err := webserverUrl("vpn.test:8080", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test:8080"
	if url, err := webserverUrl("vpn.test:8080", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test:8888"
	if url, err := webserverUrl("vpn.test", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test"
	if url, err := webserverUrl("vpn.test", "127.0.0.1:443", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:443"
	if url, err := webserverUrl("vpn.test", "127.0.0.1:443", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test"
	if url, err := webserverUrl("vpn.test:443", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test"
	if url, err := webserverUrl("vpn.test:80", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:443"
	if url, err := webserverUrl("vpn.test:443", "192.168.122.1:80", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test"
	if url, err := webserverUrl("https://vpn.test", "127.0.0.1:80", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://127.0.0.1:8888"
	if url, err := webserverUrl("", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("expected to use listen address when domain is empty")
	}

	expected = "https://127.0.0.1:8888"
	if url, err := webserverUrl("", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("expected to use listen address when domain is empty (tls)")
	}

	if _, err := webserverUrl("", "", false); err == nil {
		t.Fatal("expected error on empty domain and empty listen address")
	}

}
