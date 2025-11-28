package data

import "testing"

func TestDomainToUrl(t *testing.T) {

	expected := "http://vpn.test:8888"
	if url, err := domainToUrl("vpn.test", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:8080"
	if url, err := domainToUrl("vpn.test:8080", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test:8080"
	if url, err := domainToUrl("vpn.test:8080", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test:8888"
	if url, err := domainToUrl("vpn.test", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test"
	if url, err := domainToUrl("vpn.test", "127.0.0.1:443", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:443"
	if url, err := domainToUrl("vpn.test", "127.0.0.1:443", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "https://vpn.test"
	if url, err := domainToUrl("vpn.test:443", "127.0.0.1:8888", true); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test"
	if url, err := domainToUrl("vpn.test:80", "127.0.0.1:8888", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	expected = "http://vpn.test:443"
	if url, err := domainToUrl("vpn.test:443", "192.168.122.1:80", false); url != expected || err != nil {
		t.Fatal("got", url, "expected: ", expected)
	}

	if _, err := domainToUrl("", "127.0.0.1:8888", false); err == nil {
		t.Fatal("expected error on empty domain")
	}

}
