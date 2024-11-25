package autotls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// You need to implement this interface for the ACME client
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	// Replace these with your values
	acmeEmail := "your-email@example.com"

	cfEmail := "some@email.com"

	domain := "your-domain.com"
	cfAPIToken := os.Getenv("CF_API_TOKEN")

	// Create a user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: acmeEmail,
		key:   privateKey,
	}

	acmeConfig := lego.NewConfig(&myUser)

	// This will help you get staging certificates while testing
	acmeConfig.CADirURL = lego.LEDirectoryStaging
	// Use this for production
	// config.CADirURL = lego.LEDirectoryProduction

	// Create a new ACME client
	client, err := lego.NewClient(acmeConfig)
	if err != nil {
		log.Fatal(err)
	}

	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.AuthEmail = cfEmail
	cfConfig.AuthKey = cfAPIToken

	// Configure Cloudflare provider
	cfProvider, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Set Cloudflare as the DNS provider
	err = client.Challenge.SetDNS01Provider(cfProvider,
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
	)
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
