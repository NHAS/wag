package methods

import (
	"encoding/hex"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
	"github.com/NHAS/wag/users"
	"github.com/NHAS/wag/utils"
	"github.com/NHAS/wag/webserver/authenticators"
	"github.com/NHAS/wag/webserver/resources"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

type Oidc struct {
	provider rp.RelyingParty
}

func (o Oidc) state() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (o *Oidc) Init(settings map[string]string) error {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return errors.New("failed to get random key: " + err.Error())
	}

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	u, err := url.Parse(settings["DomainURL"])
	if err != nil {
		return err
	}

	u.Path = path.Join(u.Path, "/authorise/oidc/")
	log.Println("OIDC callback: ", u.String())

	log.Println("Connecting to OIDC provider")
	o.provider, err = rp.NewRelyingPartyOIDC(settings["IssuerURL"], settings["ClientID"], settings["ClientSecret"], u.String(), []string{"openid"}, options...)
	if err != nil {
		return err
	}

	return nil
}

func (o *Oidc) Type() string {
	return authenticators.OidcMFA
}

func (o *Oidc) FriendlyName() string {
	return "Single Sign On"
}

func (o *Oidc) RegistrationEndpoint(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", 400)
		return
	}

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", 400)
		return
	}

	log.Println(user.Username, clientTunnelIp, "registering with oidc")

	err = data.SetUserMfa(user.Username, o.provider.Issuer(), authenticators.OidcMFA)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to set authentication method as oidc key to db:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	rp.AuthURLHandler(o.state, o.provider)(w, r)
}

func (o *Oidc) AuthorisationEndpoint(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", 400)
		return
	}

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {
		// Will set enforcing on first use
		err = user.Authenticate(clientTunnelIp.String(), user.GetMFAType(), func(issuer, username string) error {

			if issuer != rp.Issuer() {
				return errors.New("stored issuer " + issuer + " did not equal actual issuer: " + rp.Issuer())
			}

			if info.GetPreferredUsername() != username {
				return errors.New("returned username did not equal device associated username")
			}

			return nil
		})

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())

			msg, _ := resultMessage(err)
			if strings.Contains(err.Error(), "returned username") {
				msg = "username " + user.Username + " not associated with device, device owned by " + info.GetPreferredUsername()
			}

			w.WriteHeader(http.StatusUnauthorized)
			renderTemplate(w, resources.OIDCMFATemplate, msg, rp.GetEndSessionEndpoint())
			return
		}

		log.Println(user.Username, clientTunnelIp, "authorised")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), o.provider)(w, r)
}

func (o *Oidc) PromptHandler(w http.ResponseWriter, r *http.Request, username, ip string) {
	rp.AuthURLHandler(o.state, o.provider)(w, r)
}

func (o *Oidc) RegistrationHandler(w http.ResponseWriter, r *http.Request, username, ip string) {
	o.RegistrationEndpoint(w, r)
}
