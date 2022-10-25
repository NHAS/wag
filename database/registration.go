package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

func GetRegistrationToken(token string) (username string, err error) {

	minTime := time.After(1 * time.Second)

	err = database.QueryRow(`
		SELECT token, username FROM RegistrationTokens
		WHERE
			token = ?
	`, token).Scan(&token, &username)

	<-minTime

	return
}

// Returns list of tokens in a map of token : username
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

func DeleteRegistrationToken(identifier string) error {
	_, err := database.Exec(`
		DELETE FROM
			RegistrationTokens
		WHERE
			token = ? or username = ?
	`, identifier, identifier)
	return err
}

// Randomly generate a token for a specific username
func GenerateToken(username string) (token string, err error) {
	tokenBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}

	token = hex.EncodeToString(tokenBytes)
	err = AddRegistrationToken(token, username)

	return
}

// Add a token to the database for the specific username, may fail of the token does not meet complexity requirements
func AddRegistrationToken(token, username string) error {
	if len(token) < 32 {
		return errors.New("Registration token is too short")
	}

	if !allowedTokenCharacters.Match([]byte(token)) {
		return errors.New("Registration token contains illegal characters (allowed characters a-z A-Z - . _ )")
	}

	//Technically racy, but to no real effect

	var u string
	err := database.QueryRow("SELECT username FROM Devices WHERE username = ?", username).Scan(&u)
	if err == nil {
		return errors.New("cannot create registration token for username that already exists")
	}

	if err != nil && err != sql.ErrNoRows {
		return errors.New("failed to create registration token: " + err.Error())
	}

	_, err = database.Exec(`
		INSERT INTO
			RegistrationTokens (token, username)
		VALUES
			(?, ?)
	`, token, username)

	return err
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
