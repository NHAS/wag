package authenticators

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type entry struct {
	usetime time.Time
	code    string
}

// Make sure that one time passwords (OTPs) are truly one time, store used codes
var lockULock sync.Mutex
var usedCodes = map[string]entry{}

func Totp(w http.ResponseWriter, r *http.Request) Authenticator {

	return func(mfaSecret, mfaType, username string) error {
		if mfaType != TotpMFA {
			return errors.New("wrong mfa type")
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad request", 400)
			return err
		}

		code := r.FormValue("code")

		key, err := otp.NewKeyFromURL(mfaSecret)
		if err != nil {
			return err
		}

		if !totp.Validate(code, key.Secret()) {
			return errors.New("code does not match expected")
		}

		lockULock.Lock()

		e := usedCodes[username]
		if e.code == code && e.usetime.Add(30*time.Second).After(time.Now()) {
			return errors.New("code already used")
		}

		usedCodes[username] = entry{code: code, usetime: time.Now()}
		lockULock.Unlock()

		return nil
	}
}
