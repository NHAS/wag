package authenticators

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/webserver/session"
	"github.com/NHAS/webauthn/protocol"
	"github.com/NHAS/webauthn/webauthn"
)

func WebauthnLogin(w http.ResponseWriter, r *http.Request, webauthnConfig *webauthn.WebAuthn) Authenticator {
	return func(mfaSecret, mfaType, username string) error {

		if mfaType != WebauthnMFA {
			return errors.New("wrong mfa type")
		}

		var webauthnUser WebauthnUser
		err := webauthnUser.UnmarshalJSON([]byte(mfaSecret))
		if err != nil {
			log.Println("failed to unmarshal db object:", err)
			return err
		}

		// load the session data
		cookie, err := r.Cookie("authentication")
		if err != nil {
			return err
		}

		sessionData, err := session.GetSession(cookie.Value)
		if err != nil {
			return err
		}

		session, ok := sessionData.(*webauthn.SessionData)
		if !ok {
			return errors.New("session data could not be turned into WebauthnSessionData")
		}

		c, err := webauthnConfig.FinishLogin(webauthnUser, *session, r)
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
		err = data.SetUserMfa(username, string(webauthdata), WebauthnMFA)
		if err != nil {
			return err
		}

		return nil
	}
}

func WebauthnRegister(w http.ResponseWriter, r *http.Request, webauthnConfig *webauthn.WebAuthn) Authenticator {
	return func(mfaSecret, mfaType, username string) error {
		if mfaType != WebauthnMFA {
			return errors.New("wrong mfa type")
		}

		var webauthnUser WebauthnUser
		err := webauthnUser.UnmarshalJSON([]byte(mfaSecret))
		if err != nil {
			return err
		}

		cookie, err := r.Cookie("registration")
		if err != nil {
			return err
		}

		sessionData, err := session.GetSession(cookie.Value)
		if err != nil {
			return err
		}

		webauthnSession, ok := sessionData.(*webauthn.SessionData)
		if !ok {
			return errors.New("could not get webauthn session back")
		}

		credential, err := webauthnConfig.FinishRegistration(webauthnUser, *webauthnSession, r)
		if err != nil {
			return err
		}

		webauthnUser.AddCredential(*credential)

		webauthdata, err := webauthnUser.MarshalJSON()
		if err != nil {
			return err
		}

		err = data.SetUserMfa(username, string(webauthdata), WebauthnMFA)
		if err != nil {

			return err
		}

		session.DeleteSession(cookie.Value)

		return nil
	}
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
	binary.PutUvarint(buf, uint64(u.id))
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

// WebAuthnCredentials returns credentials owned by the user
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

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
