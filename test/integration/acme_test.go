package integration

import "testing"

func TestAcmeProviderDetails(t *testing.T) {

	const providerUrl = "https://test.example.com"
	err := ctrl.SetAcmeProvider(providerUrl)
	if err != nil {
		t.Fatal("should be able to set acme provider with valid url: ", err)
	}

	url, err := ctrl.GetAcmeProvider()
	if err != nil {
		t.Fatal("should be able to get acme provider url: ", err)
	}

	if url != providerUrl {
		t.Fatal("provider url was incorrect")
	}
}

func TestAcmeProviderInvalidUrl(t *testing.T) {

	err := ctrl.SetAcmeProvider("wagghh")
	if err == nil {
		t.Fatal("shouldnt be able to set something that is not a url")
	}

	err = ctrl.SetAcmeProvider("")
	if err != nil {
		t.Fatal("should be able to set as nothing: ", err)
	}
}

func TestAcmeEmail(t *testing.T) {

	const email = "test@example.com"
	err := ctrl.SetAcmeEmail(email)
	if err != nil {
		t.Fatal("should be able to set acme email with valid email: ", err)
	}

	fetchedEmail, err := ctrl.GetAcmeEmail()
	if err != nil {
		t.Fatal("should be able to get acme email: ", err)
	}

	if email != fetchedEmail {
		t.Fatal("email was incorrect")
	}
}

func TestAcmeEmailInvalid(t *testing.T) {

	err := ctrl.SetAcmeEmail("not_an_email")
	if err == nil {
		t.Fatal("invalid email should be rejected")
	}

	err = ctrl.SetAcmeEmail("")
	if err != nil {
		t.Fatal("unsetting email should be allowed: ", err)
	}

}
