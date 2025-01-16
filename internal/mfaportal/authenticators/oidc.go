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
	"strings"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/mfaportal/resources"
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

func (o *Oidc) LogoutPath() string {
	return o.provider.GetEndSessionEndpoint()
}

func (o *Oidc) Init(fw *router.Firewall) error {

	o.fw = fw

	key, err := utils.GenerateRandom(32)
	if err != nil {
		return errors.New("failed to get random key: " + err.Error())
	}

	hashkey, err := utils.GenerateRandom(32)
	if err != nil {
		return errors.New("failed to get random hash key: " + err.Error())
	}

	o.details, err = data.GetOidc()
	if err != nil {
		return err
	}

	cookieHandler := httphelper.NewCookieHandler([]byte(hashkey), []byte(key), httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	domain, err := data.GetTunnelDomainUrl()
	if err != nil {
		return err
	}

	u, err := url.Parse(domain)
	if err != nil {
		return err
	}

	u.Path = path.Join(u.Path, "/authorise/oidc/")
	log.Println("OIDC callback: ", u.String())
	log.Println("Connecting to OIDC provider: ", o.details.IssuerURL)

	if len(o.details.Scopes) == 0 {
		o.details.Scopes = []string{"openid"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	o.provider, err = rp.NewRelyingPartyOIDC(ctx, o.details.IssuerURL, o.details.ClientID, o.details.ClientSecret, u.String(), o.details.Scopes, options...)
	cancel()
	if err != nil {
		return err
	}

	log.Println("Connected!")

	return nil
}

func (o *Oidc) Type() string {
	return string(types.Oidc)
}

func (o *Oidc) FriendlyName() string {
	return "Single Sign On"
}

func (o *Oidc) RegistrationAPI(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if o.fw.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	log.Println(user.Username, clientTunnelIp, "registering with oidc")

	value, _ := json.Marshal(issuer{
		Issuer:  o.provider.Issuer(),
		Subject: "", // Empty is unconfigured waiting for first login
	})

	err = data.SetUserMfa(user.Username, string(value), o.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to set authentication method as oidc key to db:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomHex(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) AuthorisationAPI(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if o.fw.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		groupsIntf, ok := tokens.IDTokenClaims.Claims[o.details.GroupsClaimName].([]interface{})
		if !ok {
			log.Println("Error, could not convert group claim to []string, probably error in oidc idP configuration")

			http.Error(w, "Server Error", http.StatusInternalServerError)

			return
		}

		suppliedUsername := info.PreferredUsername

		if len(o.details.DeviceUsernameClaim) != 0 {

			deviceUsernameClaim, ok := tokens.IDTokenClaims.Claims[o.details.DeviceUsernameClaim].(string)
			if !ok {
				log.Println("Error, Device Username Claim set but idP has not set attribute in users token")
				http.Error(w, "Server Error", http.StatusInternalServerError)
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
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}
			groups = append(groups, "group:"+conv)
		}

		// Will set enforcing on first use
		challenge, err := user.Authenticate(clientTunnelIp.String(), user.GetMFAType(), func(issuerString, username string) error {

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

			msg, _ := resultMessage(err)
			if strings.Contains(err.Error(), "returned username") {
				msg = fmt.Sprintf("username %q not associated with device, device owned by %q", info.PreferredUsername, user.Username)
			}

			w.WriteHeader(http.StatusUnauthorized)

			// Preserve original error
			err2 := resources.Render("oidc_error.html", w, &resources.Msg{
				HelpMail:   data.GetHelpMail(),
				NumMethods: NumberOfMethods(),
				Message:    msg,
				URL:        rp.GetEndSessionEndpoint(),
			})

			if err2 != nil {
				log.Println(user.Username, clientTunnelIp, "error rendering oidc_error.html: ", err2)
			}

			return
		}

		IssueChallengeTokenCookie(w, r, challenge)

		log.Println(user.Username, clientTunnelIp, "used sso to login with groups: ", groups)

		log.Println(user.Username, clientTunnelIp, "authorised")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), o.provider)(w, r)
}

func (o *Oidc) MFAPromptUI(w http.ResponseWriter, r *http.Request, _, _ string) {
	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomHex(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) RegistrationUI(w http.ResponseWriter, r *http.Request, _, _ string) {
	o.RegistrationAPI(w, r)
}
