package main

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var database *sql.DB
var allowedTokenCharacters = regexp.MustCompile("[a-zA-Z0-9\\-\\_\\.]+")

func LoadDb(path string) error {

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	database = db

	_, err = database.Exec("CREATE TABLE IF NOT EXISTS RegistrationTokens ( token string primary key, username string not null );")
	if err != nil {
		return err
	}

	_, err = database.Exec("CREATE TABLE IF NOT EXISTS Totp ( address string primary key, publickey string, username string, url string not null, enforcing string );")
	if err != nil {
		return err
	}

	return nil
}

func ValidateTotpCode(address, code string) (username string, err error) {

	var url string
	err = database.QueryRow(`
		SELECT username, url FROM Totp
		WHERE
			address = ?
	`, address).Scan(&username, &url)

	if err != nil {
		return
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return "", err
	}

	if !totp.Validate(code, key.Secret()) {
		return username, errors.New("Code does not match expected")
	}

	return
}

func isEnforcingMFA(address string) bool {
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

func GetMFASecret(address string) (*otp.Key, error) {
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
		return nil, errors.New("MFA is set to enforcing, cannot reveal secrete now.")
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return nil, err
	}

	return key, nil
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

func GetDevices() (map[string][]string, error) {

	rows, err := database.Query("SELECT address, publickey, username, enforcing FROM Totp ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)
	for rows.Next() {
		var address, publickey, username string
		var enforcing sql.NullString
		err = rows.Scan(&address, &publickey, &username, &enforcing)
		if err != nil {
			return nil, err
		}

		result[address] = []string{publickey, username, fmt.Sprintf("%t", enforcing.Valid)}
	}

	return result, nil

}

func DeleteDevice(address string) error {
	_, err := database.Exec(`
		DELETE FROM
			Totp
		WHERE
			address = ?
	`, address)
	return err
}

func ArmMFAFirstUse(address, publickey, username string) error {

	if net.ParseIP(address) == nil {
		return errors.New("Address '" + address + "' cannot be parsed as IP, invalid")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Config.Issuer,
		AccountName: username,
	})
	if err != nil {
		return err
	}

	//Leaves enforcing null
	_, err = database.Exec(`
	INSERT INTO
		Totp (address, publickey, username, url)
	VALUES
		(?, ?, ?, ?)
`, address, publickey, username, key.URL())

	return err
}

func GetRegistrationToken(token string) (username string, err error) {

	err = database.QueryRow(`
		SELECT token, username FROM RegistrationTokens
		WHERE
			token = ?
	`, token).Scan(&token, &username)

	return
}

//Returns list of tokens in a map of token : username
func GetRegistrationTokens() (map[string]string, error) {
	rows, err := database.Query("SELECT * from RegistrationTokens ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for rows.Next() {
		var token, username string
		err = rows.Scan(&token, &username)
		if err != nil {
			return nil, err
		}
		result[token] = username
	}

	return result, nil
}

func DeleteRegistrationToken(token string) error {
	_, err := database.Exec(`
		DELETE FROM
			RegistrationTokens
		WHERE
			token = ?
	`, token)
	return err
}

func GenerateToken(username string) (token string, err error) {
	tokenBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}

	token = hex.EncodeToString(tokenBytes)
	err = AddRegistrationToken(token, username)

	return
}

func AddRegistrationToken(token, username string) error {
	if len(token) < 32 {
		return errors.New("Registration token is too short")
	}

	if !allowedTokenCharacters.Match([]byte(token)) {
		return errors.New("Registration token contains illegal characters (allowed characters a-z A-Z - . _ )")
	}

	_, err := database.Exec(`
		INSERT INTO
			RegistrationTokens (token, username)
		VALUES
			(?, ?)
	`, token, username)

	return err
}
