package authenticators

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type entry struct {
	usetime time.Time
	code    string
}

// Make sure that one time passwords (OTPs) are truly one time, store used codes
var (
	lockULock sync.Mutex
	usedCodes = map[string]entry{}
)

type Totp struct {
	enable

	fw *router.Firewall
}

func (t *Totp) Initialise(fw *router.Firewall, initiallyEnabled bool) (routes *http.ServeMux, err error) {

	t.fw = fw

	t.enable = enable(initiallyEnabled)

	routes = http.NewServeMux()

	registrationEndpoints := http.NewServeMux()
	registrationEndpoints.HandleFunc("POST /details", t.getTotpSecret)
	registrationEndpoints.HandleFunc("POST /complete", t.authorise("Incorrect TOTP Code. Registration incomplete."))

	routes.Handle("/register",
		http.StripPrefix(
			"/register",
			isUnauthed(
				ensureUnregistered(registrationEndpoints, fw),
				fw,
			),
		),
	)

	routes.HandleFunc("POST /authorise", isUnauthedFunc(t.authorise("Incorrect TOTP Code."), fw))

	return routes, nil
}

func (t *Totp) ReloadSettings() error {
	return nil
}

func (t *Totp) Type() string {
	return string(types.Totp)
}

func (t *Totp) FriendlyName() string {
	return "Time Based Code"
}

func (t *Totp) getTotpSecret(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "Bad request",
		}, http.StatusBadRequest)
		return
	}

	issuer, err := data.GetIssuer()
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to get issuer from datastore")

		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "Failed to get issuer data",
		}, http.StatusInternalServerError)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Username,
	})
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "generate key failed:", err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "Generating TOTP code failed",
		}, http.StatusInternalServerError)
		return
	}

	err = data.SetUserMfa(user.Username, key.URL(), t.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to save totp key to db:", err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "Saving TOTP code failed",
		}, http.StatusInternalServerError)
		return
	}

	image, err := key.Image(200, 200)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "generating image failed:", err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "Failed to generate TOTP png",
		}, http.StatusInternalServerError)
		return
	}

	var buff bytes.Buffer
	err = png.Encode(&buff, image)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "encoding mfa secret as png failed:", err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  "encoding TOTP QRCode PNG failed",
		}, http.StatusInternalServerError)
		return
	}

	jsonResponse(w, AuthResponse{
		Status: "challenge",
		Data: TOTPSecretDTO{
			ImageData:   "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
			Key:         key.Secret(),
			AccountName: key.AccountName(),
		},
	}, http.StatusOK)
}

func (t *Totp) authorise(failureMessage string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientTunnelIp := utils.GetIPFromRequest(r)
		user := users.GetUserFromContext(r.Context())

		err := user.Authenticate(clientTunnelIp.String(), t.Type(), t.AuthoriseFunc(w, r))

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			jsonResponse(w, AuthResponse{
				Status: "error",
				Error:  failureMessage,
			}, http.StatusUnauthorized)
			return
		}

		log.Println(user.Username, clientTunnelIp, "authorised")

		jsonResponse(w, AuthResponse{
			Status: "success",
		}, http.StatusOK)
	}
}
func (t *Totp) AuthoriseFunc(w http.ResponseWriter, r *http.Request) types.AuthenticatorFunc {
	return func(mfaSecret, username string) error {
		defer r.Body.Close()

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var totpDetails TOTPRequestDTO
		err := dec.Decode(&totpDetails)
		if err != nil {
			return fmt.Errorf("failed to decode totp code: %w", err)
		}

		key, err := otp.NewKeyFromURL(mfaSecret)
		if err != nil {
			return err
		}

		lockULock.Lock()
		defer lockULock.Unlock()

		if !totp.Validate(totpDetails.Code, key.Secret()) {
			return errors.New("code does not match expected")
		}

		e := usedCodes[username]
		if e.code == totpDetails.Code && e.usetime.Add(30*time.Second).After(time.Now()) {
			return errors.New("code already used")
		}

		usedCodes[username] = entry{code: totpDetails.Code, usetime: time.Now()}

		return nil
	}
}
