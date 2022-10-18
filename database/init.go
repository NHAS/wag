package database

import (
	"bytes"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"

	"github.com/NHAS/wag/database/migrations"
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

	filesList, err := migrations.Files.ReadDir(".")
	if err != nil {
		panic(err)
	}

	var dbVersion int
	err = database.QueryRow("PRAGMA user_version;").Scan(&dbVersion)
	if err != nil {
		return fmt.Errorf("unable to get database version: %v", err)
	}

	for _, migration := range filesList {
		if !migration.IsDir() {
			contents, _ := migrations.Files.ReadFile(migration.Name())
			lines := bytes.Split(contents, []byte("\n"))

			if len(lines) < 1 {
				panic("migration file is too short to be valid")
			}

			if !bytes.HasPrefix(lines[0], []byte("-- version ")) {
				panic("migration file does not have a version assigned to it")
			}

			migrationVersion, err := strconv.Atoi(string(bytes.TrimSpace(bytes.Split(lines[0], []byte("-- version "))[1])))
			if err != nil {
				panic("migration version could not be converted into a number: " + err.Error())
			}

			if migrationVersion <= dbVersion {
				continue
			}

			fmt.Println("Running migration: ", migration.Name())

			transact, err := database.Begin()
			if err != nil {
				return fmt.Errorf("unable to begin sql transaction: %v", err)
			}

			for _, line := range lines {
				_, err = transact.Exec(string(line))
				if err != nil {
					transact.Rollback()
					return fmt.Errorf("unable to build database error while applying %s: %v", migration.Name(), err)
				}
			}

			// Doing PRAGMA user_version = ? fails with a syntax error
			_, err = transact.Exec(`PRAGMA user_version = ` + fmt.Sprintf("%d", migrationVersion))
			if err != nil {
				transact.Rollback()
				return fmt.Errorf("unable to set db version %s: %v", migration.Name(), err)
			}

			if err := transact.Commit(); err != nil {
				transact.Rollback()
				return fmt.Errorf("unable to commit database change during %s: %v", migration.Name(), err)
			}

		}
	}

	return nil
}
