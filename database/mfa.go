package database

import (
	"database/sql"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func ShowSecret(address string) (*otp.Key, error) {
	var url string
	var enforcing sql.NullString
	err := database.QueryRow(`
		SELECT url, enforcing FROM Totp
		WHERE
		address = ?
	`, address).Scan(&url, &enforcing)
	if err != nil {
		return nil, err
	}

	if enforcing.Valid {
		return nil, errors.New("MFA is set to enforcing, cannot reveal secret.")
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func SetAttempts(address string, attempts int) error {
	_, err := database.Exec(`
	UPDATE 
		Totp
	SET
		attempts = ?
	WHERE
		address = ?
	`, attempts, address)

	if err != nil {
		return errors.New("Unable to set number of account attempts: " + err.Error())
	}

	return nil
}

func IsEnforcingMFA(address string) bool {
	var enforcing sql.NullString
	err := database.QueryRow(`
	SELECT enforcing FROM Totp
	WHERE
		address = ?
`, address).Scan(&enforcing)

	// Fail closed
	if err != nil {
		return true
	}

	return enforcing.Valid
}

func SetMFAEnforcing(address string) error {
	_, err := database.Exec(`
	UPDATE 
		Totp
	SET
		enforcing = ?
	WHERE
		address = ?
	`, time.Now().Format(time.RFC3339), address)

	return err
}

func CreateMFAEntry(address, publickey, username string) (Device, error) {

	if net.ParseIP(address) == nil {
		return Device{}, errors.New("Address '" + address + "' cannot be parsed as IP, invalid")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return Device{}, err
	}

	//Leaves enforcing null
	_, err = database.Exec(`
	INSERT INTO
		Totp (address, publickey, username, url, attempts)
	VALUES
		(?, ?, ?, ?, ?)
`, address, publickey, username, key.URL(), 0)

	return Device{
		Address:   address,
		Publickey: publickey,
		Username:  username,
		Enforcing: false,
	}, err

}

type entry struct {
	usetime time.Time
	code    string
}

var lockULock sync.Mutex
var usedCodes = map[string]entry{}

func Authenticate(address, code string) (err error) {

	_, err = database.Exec(`UPDATE Totp SET attempts = attempts + 1 WHERE address = ? and attempts <= ?`, address, lockoutPolicy)
	if err != nil {
		return
	}

	var url string
	var attempts int

	err = database.QueryRow(`SELECT url, attempts FROM Totp WHERE address = ?`, address).Scan(&url, &attempts)
	if err != nil {
		return
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return
	}

	if attempts > lockoutPolicy {
		return errors.New("account is locked")
	}

	if !totp.Validate(code, key.Secret()) {
		return errors.New("code does not match expected")
	}

	lockULock.Lock()

	e := usedCodes[address]
	if e.code == code && e.usetime.Add(30*time.Second).After(time.Now()) {
		return errors.New("code already used")
	}

	usedCodes[address] = entry{code: code, usetime: time.Now()}
	lockULock.Unlock()

	return
}
