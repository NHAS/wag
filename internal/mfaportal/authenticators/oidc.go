package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type issuer struct {
	Issuer  string
	Subject string
}

type Oidc struct {
	enable

	provider rp.RelyingParty
	details  data.OIDC
	fw       *router.Firewall
}

func (o *Oidc) GetRoutes(fw *router.Firewall) (routes *http.ServeMux, err error) {

	o.fw = fw

	routes = http.NewServeMux()
	routes.HandleFunc("GET /register", isUnauthedFunc(isUnregisteredFunc(o.register), fw))

	authorisationEndpoints := http.NewServeMux()
	authorisationEndpoints.HandleFunc("GET /start", o.startAuthorisation)
	authorisationEndpoints.HandleFunc("GET /callback", o.oidcCallbackFinishAuth)
	//For iDPs that dont respect the trailing slash
	// https://github.com/NHAS/wag/issues/129
	authorisationEndpoints.HandleFunc("GET /callback/", o.oidcCallbackFinishAuth)

	routes.Handle("/authorise/",
		http.StripPrefix(
			"/authorise",
			isUnauthed(
				authorisationEndpoints,
				fw,
			),
		),
	)

	return routes, nil
}

func (o *Oidc) Initialise() error {

	key, err := utils.GenerateRandom(32)
	if err != nil {
		return errors.New("failed to get random key: " + err.Error())
	}

	hashkey, err := utils.GenerateRandom(32)
	if err != nil {
		return errors.New("failed to get random hash key: " + err.Error())
	}

	cookieHandler := httphelper.NewCookieHandler([]byte(hashkey), []byte(key), httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	o.details, err = data.GetOidc()
	if err != nil {
		return err
	}

	domain, err := data.GetTunnelDomainUrl()
	if err != nil {
		return err
	}

	u, err := url.Parse(domain)
	if err != nil {
		return err
	}

	u.Path = path.Join(u.Path, "/api/oidc/authorise/callback")
	log.Println("OIDC callback: ", u.String())

	if len(o.details.Scopes) == 0 {
		o.details.Scopes = []string{"openid"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	o.provider, err = rp.NewRelyingPartyOIDC(ctx, o.details.IssuerURL, o.details.ClientID, o.details.ClientSecret, u.String(), o.details.Scopes, options...)
	cancel()
	if err != nil {
		return err
	}

	log.Println("Connected to OIDC provider: ", o.details.IssuerURL)
	return nil
}

func (o *Oidc) Type() string {
	return string(types.Oidc)
}

func (o *Oidc) FriendlyName() string {
	return "Single Sign On"
}

func (o *Oidc) register(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	user := users.GetUserFromContext(r.Context())
	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	log.Println(user.Username, clientTunnelIp, "registering with oidc")

	value, _ := json.Marshal(issuer{
		Issuer:  o.provider.Issuer(),
		Subject: "", // Empty is unconfigured waiting for first login
	})

	err := data.SetUserMfa(user.Username, string(value), o.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to set authentication method as oidc key to db:", err)
		http.Redirect(w, r, "/error", http.StatusSeeOther)
		return
	}

	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomHex(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) startAuthorisation(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if o.fw.IsAuthed(clientTunnelIp.String()) {
		http.Redirect(w, r, "/success", http.StatusSeeOther)
		return
	}

	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomHex(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) oidcCallbackFinishAuth(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if o.fw.IsAuthed(clientTunnelIp.String()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user := users.GetUserFromContext(r.Context())

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		groupsIntf, ok := tokens.IDTokenClaims.Claims[o.details.GroupsClaimName].([]interface{})
		if !ok {
			log.Println("Error, could not convert group claim to []string, probably error in oidc idP configuration")
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return
		}

		suppliedUsername := info.PreferredUsername

		if len(o.details.DeviceUsernameClaim) != 0 {

			deviceUsernameClaim, ok := tokens.IDTokenClaims.Claims[o.details.DeviceUsernameClaim].(string)
			if !ok {
				log.Println("Error, Device Username Claim set but idP has not set attribute in users token")
				http.Redirect(w, r, "/error", http.StatusSeeOther)
				return
			}

			suppliedUsername = deviceUsernameClaim

		}

		// Rather ugly way of converting []interface{} into []string{}
		var groups []string
		for i := range groupsIntf {
			conv, ok := groupsIntf[i].(string)
			if !ok {
				log.Println("Error, could not convert group claim to string, probably mistake in your OIDC idP configuration")
				http.Redirect(w, r, "/error", http.StatusSeeOther)
				return
			}
			groups = append(groups, "group:"+conv)
		}

		// Will set enforcing on first use
		err := user.Authenticate(clientTunnelIp.String(), user.GetMFAType(), func(issuerString, username string) error {

			var issuerDetails issuer
			err := json.Unmarshal([]byte(issuerString), &issuerDetails)
			if err != nil {
				return err
			}

			if issuerDetails.Issuer != rp.Issuer() {
				return fmt.Errorf("stored issuer %q did not equal actual issuer: %q", issuerDetails.Issuer, rp.Issuer())
			}

			// On first OIDC login this will be unset
			if issuerDetails.Subject == "" {

				issuerDetails.Subject = info.Subject

				value, _ := json.Marshal(issuerDetails)

				err = data.SetUserMfa(user.Username, string(value), o.Type())
				if err != nil {
					return fmt.Errorf("unable to set oidc subject: %s", err)
				}
			}

			if issuerDetails.Subject != info.Subject {
				log.Printf("Error logging in user, idP supplied device username (%q) does not equal expected username (%q)", suppliedUsername, username)
				return fmt.Errorf("idp subject %q is not equal to subject %q associated with username %q", info.Subject, issuerDetails.Subject, username)
			}

			if suppliedUsername != username {
				log.Printf("Error logging in user, idP supplied username (%q) does not equal username (%q) associated with device", suppliedUsername, username)
				return errors.New("user is not associated with device")
			}

			return data.SetUserGroupMembership(username, groups)
		})

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return
		}

		log.Println(user.Username, clientTunnelIp, "used sso to login with groups: ", groups)

		log.Println(user.Username, clientTunnelIp, "authorised")

		http.Redirect(w, r, "/success", http.StatusSeeOther)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), o.provider)(w, r)
}
