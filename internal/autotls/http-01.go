package autotls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func test() {
	// Replace these with your values
	email := "your-email@example.com"
	domain := "your-domain.com"

	// Create a user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This will help you get staging certificates while testing
	config.CADirURL = lego.LEDirectoryStaging
	// Use this for production
	// config.CADirURL = lego.LEDirectoryProduction

	// Create a new ACME client
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Create HTTP-01 provider
	httpProvider := http01.NewProviderServer("", "80")

	// Set HTTP-01 as the challenge provider
	err = client.Challenge.SetHTTP01Provider(httpProvider)
	if err != nil {
		log.Fatal(err)
	}

	// Register user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	_, err = client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully obtained certificates!")
}
