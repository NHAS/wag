package database

import (
	"database/sql"
	"errors"
	"net"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GetAuthenticationAttemptsLeft(username string) (int, error) {
	var attempts int
	err := database.QueryRow(`
		SELECT attempts FROM Totp
		WHERE
			username = ?
	`, username).Scan(&attempts)

	if err != nil {
		return 0, err
	}

	return attempts, nil
}

func SetAttempts(username string, attempts int) error {
	_, err := database.Exec(`
	UPDATE 
		Totp
	SET
		attempts = ?
	WHERE
		username = ?
	`, attempts, username)

	if err != nil {
		return errors.New("Unable to set number of account attempts: " + err.Error())
	}

	return nil
}

func IsEnforcingMFA(username string) bool {
	var enforcing sql.NullString
	err := database.QueryRow(`
	SELECT enforcing FROM Totp
	WHERE
		username = ?
`, username).Scan(&enforcing)

	// Fail closed
	if err != nil {
		return true
	}

	return enforcing.Valid
}

func SetMFAEnforcing(username string) error {
	_, err := database.Exec(`
	UPDATE 
		Totp
	SET
		enforcing = ?
	WHERE
		username = ?
	`, time.Now().Format(time.RFC3339), username)

	return err
}

func CreateMFAEntry(address, publickey, username string) error {

	if net.ParseIP(address) == nil {
		return errors.New("Address '" + address + "' cannot be parsed as IP, invalid")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return err
	}

	//Leaves enforcing null
	_, err = database.Exec(`
	INSERT INTO
		Totp (address, publickey, username, url, attempts)
	VALUES
		(?, ?, ?, ?, ?)
`, address, publickey, username, key.URL(), 0)

	return err
}

func Authenticate(address, code string) (username string, err error) {

	_, err = database.Exec(`UPDATE Totp SET attempts = attempts + 1 WHERE address = ? and attempts <= ?`, address, lockoutPolicy)
	if err != nil {
		return
	}

	var url string
	var attempts int

	err = database.QueryRow(`SELECT url, attempts, username FROM Totp WHERE address = ?`, address).Scan(&url, &attempts, &username)
	if err != nil {
		return
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return
	}

	if attempts > lockoutPolicy {
		return "", errors.New("Account is locked")
	}

	if !totp.Validate(code, key.Secret()) {
		return "", errors.New("Code does not match expected")
	}

	return
}

func ShowSecret(username string) (*otp.Key, error) {
	var url string
	var enforcing sql.NullString
	err := database.QueryRow(`
		SELECT url, enforcing FROM Totp
		WHERE
			username = ?
	`, username).Scan(&url, &enforcing)
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
