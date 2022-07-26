package database

import (
	"database/sql"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
)

var (
	database               *sql.DB
	allowedTokenCharacters = regexp.MustCompile("[a-zA-Z0-9\\-\\_\\.]+")
	totpIssuer             string
	lockoutPolicy          int
)

func Load(path, issuer string, lockout int) error {

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	totpIssuer = issuer
	lockoutPolicy = lockout

	database = db

	_, err = database.Exec("CREATE TABLE IF NOT EXISTS RegistrationTokens ( token string primary key, username string not null );")
	if err != nil {
		return err
	}

	_, err = database.Exec("CREATE TABLE IF NOT EXISTS Totp ( address string primary key, publickey string, username string, url string not null, enforcing string, attempts integer not null );")
	if err != nil {
		return err
	}

	return nil
}
