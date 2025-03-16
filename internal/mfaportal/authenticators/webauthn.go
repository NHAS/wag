package authenticators

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NHAS/session"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/webauthn/protocol"
	"github.com/NHAS/webauthn/webauthn"
)

type Webauthn struct {
	enable
	sessions         *session.SessionStore[*webauthn.SessionData]
	webauthnExecutor *webauthn.WebAuthn

	fw *router.Firewall
}

func (wa *Webauthn) Initialise(fw *router.Firewall, initiallyEnabled bool) (routes *http.ServeMux, err error) {

	wa.fw = fw
	wa.enable = enable(initiallyEnabled)

	err = wa.ReloadSettings()
	if err != nil {
		return nil, err
	}

	routes = http.NewServeMux()

	registrationEndpoints := http.NewServeMux()
	registrationEndpoints.HandleFunc("POST /details", wa.getRegistrationDetails)
	registrationEndpoints.HandleFunc("POST /complete", wa.completeRegistration)

	routes.Handle("/register/",
		http.StripPrefix(
			"/register",
			isUnauthed(
				ensureUnregistered(registrationEndpoints, fw),
				fw,
			),
		),
	)

	authorisationEndpoints := http.NewServeMux()
	authorisationEndpoints.HandleFunc("GET /start", wa.startAuthorisation)
	authorisationEndpoints.HandleFunc("GET /finish", wa.finishAuthorisation)

	routes.Handle("/authorise/",
		http.StripPrefix(
			"/authorise",
			isUnauthed(
				authorisationEndpoints,
				fw,
			),
		),
	)

	wa.sessions, err = session.NewStore[*webauthn.SessionData]("authentication", "WAG-CSRF", 30*time.Minute, 1800, false)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise cookie storage for webauth: %w", err)
	}
	log.Println("Webauthn provider initialised!")

	return routes, nil
}

func (wa *Webauthn) ReloadSettings() error {
	d, err := data.GetWebauthn()
	if err != nil {
		return err
	}

	wa.webauthnExecutor, err = webauthn.New(&webauthn.Config{
		RPDisplayName: d.DisplayName,      // Display Name for your site
		RPID:          d.ID,               // Generally the domain name for your site
		RPOrigins:     []string{d.Origin}, // The origin URL for WebAuthn requests
	})
	if err != nil {
		return fmt.Errorf("failed to initialise the webuathn provider: %w", err)
	}

	return nil
}

func (wa *Webauthn) Type() string {
	return string(types.Webauthn)
}

func (wa *Webauthn) FriendlyName() string {
	return "Security Key"
}

func (wa *Webauthn) getRegistrationDetails(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	webauthnUser := NewUser(user.Username, user.Username)

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := wa.webauthnExecutor.BeginRegistration(
		webauthnUser,
		func(pkcco *protocol.PublicKeyCredentialCreationOptions) {
			pkcco.AuthenticatorSelection.UserVerification = "discouraged"
		},
	)

	if err != nil {
		log.Println(user.Username, clientTunnelIp, "error creating registration request for webauthn")
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Failed to create webauthn registration.",
		}, http.StatusInternalServerError)
		return
	}

	wa.sessions.StartSession(w, r, sessionData, nil)

	webauthdata, err := webauthnUser.MarshalJSON()
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "cant marshal json from webauthn")
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Save webauthn registration.",
		}, http.StatusInternalServerError)
		return
	}

	err = data.SetUserMfa(user.Username, string(webauthdata), wa.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "cant set user db to webauth user")
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Save MFA settings for user.",
		}, http.StatusInternalServerError)
		return
	}

	jsonResponse(w, AuthResponse{
		Status: Details,
		Data:   options,
	}, http.StatusOK)
}

func (wa *Webauthn) completeRegistration(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	err := user.Authenticate(clientTunnelIp.String(), wa.Type(),

		func(mfaSecret, username string) error {

			var webauthnUser WebauthnUser
			err := webauthnUser.UnmarshalJSON([]byte(mfaSecret))
			if err != nil {
				return err
			}

			_, sessionData := wa.sessions.GetSessionFromRequest(r)
			if sessionData == nil {
				return errors.New("session not found")
			}

			webauthnSession := *sessionData

			credential, err := wa.webauthnExecutor.FinishRegistration(webauthnUser, *webauthnSession, r)
			if err != nil {
				return err
			}

			webauthnUser.AddCredential(*credential)

			webauthdata, err := webauthnUser.MarshalJSON()
			if err != nil {
				return err
			}

			err = data.SetUserMfa(username, string(webauthdata), wa.Type())
			if err != nil {

				return err
			}

			wa.sessions.DeleteSession(w, r)

			return nil
		})

	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())

		msg, status := resultMessage(err)

		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  msg,
		}, status)

		return
	}
	log.Println(user.Username, clientTunnelIp, "registered new webauthn key")
	log.Println(user.Username, clientTunnelIp, "authorised")

	jsonResponse(w, AuthResponse{
		Status: Success,
	}, http.StatusOK)
}

func (wa *Webauthn) startAuthorisation(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	webauthUserData, err := user.MFA()
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "could not get webauthn MFA details from db:", err)

		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Failed to retrieve webauthn data.",
		}, http.StatusInternalServerError)
		return
	}

	var webauthnUser WebauthnUser
	err = webauthnUser.UnmarshalJSON([]byte(webauthUserData))
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to unmarshal db object:", err)
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Failed to parse webauthn data.",
		}, http.StatusInternalServerError)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := wa.webauthnExecutor.BeginLogin(webauthnUser, func(pkcro *protocol.PublicKeyCredentialRequestOptions) {
		pkcro.UserVerification = "discouraged"
	})
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to generate challenge (webauthn):", err)
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  "Failed to generate challenge.",
		}, http.StatusInternalServerError)
		return
	}

	wa.sessions.StartSession(w, r, sessionData, nil)

	jsonResponse(w, AuthResponse{
		Status: Success,
		Data:   options,
	}, http.StatusOK)
	log.Println(user.Username, clientTunnelIp, "begun webauthn login process (sent challenge)")

}

func (wa *Webauthn) finishAuthorisation(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	err := user.Authenticate(clientTunnelIp.String(), wa.Type(),
		func(mfaSecret, username string) error {

			var webauthnUser WebauthnUser
			err := webauthnUser.UnmarshalJSON([]byte(mfaSecret))
			if err != nil {
				log.Println("failed to unmarshal db object:", err)
				return err
			}

			// load the session data
			_, sessionData := wa.sessions.GetSessionFromRequest(r)
			if sessionData == nil {
				return errors.New("session was not found in request")
			}

			c, err := wa.webauthnExecutor.FinishLogin(webauthnUser, **sessionData, r)
			if err != nil {
				return err
			}

			//  check for cloned security keys
			if c.Authenticator.CloneWarning {
				return errors.New("cloned key detected")
			}

			webauthdata, err := webauthnUser.MarshalJSON()
			if err != nil {
				return err
			}

			// Store the updated credentials (credential counter incremented by one)
			err = data.SetUserMfa(username, string(webauthdata), wa.Type())
			if err != nil {
				return err
			}

			return nil
		})

	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err)
		msg, status := resultMessage(err)
		jsonResponse(w, AuthResponse{
			Status: Error,
			Error:  msg,
		}, status)
		return
	}

	jsonResponse(w, AuthResponse{
		Status: Success,
	}, http.StatusOK)

	log.Println(user.Username, clientTunnelIp, "authorised")
}

// WebauthnUser represents the user model
type WebauthnUser struct {
	id          uint64
	name        string
	displayName string
	credentials map[string]*webauthn.Credential
}

func (u *WebauthnUser) UnmarshalJSON(b []byte) error {
	var anon = struct {
		Id          uint64
		Name        string
		DisplayName string
		Credentials map[string]webauthn.Credential
	}{}

	if err := json.Unmarshal(b, &anon); err != nil {
		return err
	}

	u.id = anon.Id
	u.name = anon.Name
	u.displayName = anon.DisplayName
	u.credentials = make(map[string]*webauthn.Credential)

	for id := range anon.Credentials {
		longTerm := anon.Credentials[id]
		d, err := base64.StdEncoding.DecodeString(id)
		if err != nil {
			return err
		}
		//Encoding non-ascii characters into JSON seems to be broken in golang
		u.credentials[string(d)] = &longTerm
	}

	return nil
}

func (u *WebauthnUser) MarshalJSON() ([]byte, error) {
	var anon = struct {
		Id          uint64
		Name        string
		DisplayName string
		Credentials map[string]webauthn.Credential
	}{
		Id:          u.id,
		Name:        u.name,
		DisplayName: u.displayName,
		Credentials: make(map[string]webauthn.Credential),
	}

	for id, cred := range u.credentials {

		anon.Credentials[base64.StdEncoding.EncodeToString([]byte(id))] = *cred
	}

	return json.Marshal(&anon)
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string) *WebauthnUser {

	user := &WebauthnUser{}
	user.id = randomUint64()
	user.name = name
	user.displayName = displayName
	user.credentials = map[string]*webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u WebauthnUser) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, u.id)
	return buf
}

// WebAuthnName returns the user's username
func (u WebauthnUser) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u WebauthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u WebauthnUser) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *WebauthnUser) AddCredential(cred webauthn.Credential) {

	u.credentials[string(cred.ID)] = &cred

}

// WebAuthnCredential returns credential owned by the user
func (u WebauthnUser) WebAuthnCredential(ID []byte) (out *webauthn.Credential) {

	return u.credentials[string(ID)]
}

// WebAuthnCredentials returns credentials owned by the user
func (u WebauthnUser) WebAuthnCredentials() (out []*webauthn.Credential) {
	for _, cred := range u.credentials {
		out = append(out, cred)
	}

	return
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u WebauthnUser) CredentialExcludeList() []protocol.CredentialDescriptor {

	var credentialExcludeList []protocol.CredentialDescriptor
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
