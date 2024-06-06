package authenticators

import (
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
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/internal/webserver/authenticators/types"
	"github.com/NHAS/wag/internal/webserver/resources"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

type issuer struct {
	Issuer string
}

type Oidc struct {
	enable

	provider rp.RelyingParty
	details  data.OIDC
}

func (o *Oidc) LogoutPath() string {
	return o.provider.GetEndSessionEndpoint()
}

func (o *Oidc) Init() error {

	key, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return errors.New("failed to get random key: " + err.Error())
	}

	o.details, err = data.GetOidc()
	if err != nil {
		return err
	}

	cookieHandler := httphelper.NewCookieHandler([]byte(key), []byte(key), httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	domain, err := data.GetDomain()
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

	o.provider, err = rp.NewRelyingPartyOIDC(o.details.IssuerURL, o.details.ClientID, o.details.ClientSecret, u.String(), []string{"openid"}, options...)
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

	if router.IsAuthed(clientTunnelIp.String()) {
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
		Issuer: o.provider.Issuer(),
	})

	err = data.SetUserMfa(user.Username, string(value), o.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to set authentication method as oidc key to db:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomBytes(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) AuthorisationAPI(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
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

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {

		groupsIntf, ok := tokens.IDTokenClaims.GetClaim(o.details.GroupsClaimName).([]interface{})
		if !ok {
			log.Println("Error, could not convert group claim to []string, probably error in oidc idP configuration")

			http.Error(w, "Server Error", http.StatusInternalServerError)

			return
		}

		deviceUsername := info.GetPreferredUsername()

		if len(o.details.DeviceUsernameClaim) != 0 {

			deviceUsernameClaim, ok := tokens.IDTokenClaims.GetClaim(o.details.DeviceUsernameClaim).(string)
			if !ok {
				log.Println("Error, Device Username Claim set but idP has not set attribute in users token")
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			deviceUsername = deviceUsernameClaim

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
		err = user.Authenticate(clientTunnelIp.String(), user.GetMFAType(), func(issuerString, username string) error {

			var issuerDetails issuer
			err := json.Unmarshal([]byte(issuerString), &issuerDetails)
			if err != nil {
				return err
			}

			if issuerDetails.Issuer != rp.Issuer() {
				return fmt.Errorf("stored issuer %q did not equal actual issuer: %q", issuerDetails.Issuer, rp.Issuer())
			}

			if deviceUsername != username {
				log.Printf("Error logging in user, idP supplied device username (%q) does not equal expected username (%q)", deviceUsername, username)
				return errors.New("user is not associated with device")
			}

			return data.SetUserGroupMembership(username, groups)
		})

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())

			msg, _ := resultMessage(err)
			if strings.Contains(err.Error(), "returned username") {
				msg = fmt.Sprintf("username %q not associated with device, device owned by %q", info.GetPreferredUsername(), user.Username)
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

		log.Println(user.Username, clientTunnelIp, "used sso to login with groups: ", groups)

		log.Println(user.Username, clientTunnelIp, "authorised")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), o.provider)(w, r)
}

func (o *Oidc) MFAPromptUI(w http.ResponseWriter, r *http.Request, _, _ string) {
	rp.AuthURLHandler(func() string {
		r, _ := utils.GenerateRandomBytes(32)
		return r
	}, o.provider)(w, r)
}

func (o *Oidc) RegistrationUI(w http.ResponseWriter, r *http.Request, _, _ string) {
	o.RegistrationAPI(w, r)
}
