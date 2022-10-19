package migrations

import (
	"bytes"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log"
	"strconv"
)

//go:embed *.sql
var files embed.FS

func Can(db *sql.DB) (bool, error) {
	if db == nil {
		return false, errors.New("the database was nil")
	}

	var dbVersion int
	err := db.QueryRow("PRAGMA user_version;").Scan(&dbVersion)
	if err != nil {
		return false, fmt.Errorf("unable to get database version: %v", err)
	}

	filesList, err := files.ReadDir(".")
	if err != nil {
		panic(err)
	}

	for _, migration := range filesList {
		if !migration.IsDir() {
			contents, _ := files.ReadFile(migration.Name())
			lines := bytes.Split(contents, []byte("\n"))

			migrationVersion := parseMigrationFile(lines)

			if migrationVersion > dbVersion {
				return true, nil
			}
		}
	}

	return false, nil
}

func parseMigrationFile(lines [][]byte) int {

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

	return migrationVersion
}

// Do migrations on a database using the embedded migration files
// This function may panic if the files found in the embeded file system are not correctly formatted
func Do(db *sql.DB) error {
	if db == nil {
		return errors.New("the database was nil")
	}

	filesList, err := files.ReadDir(".")
	if err != nil {
		panic(err)
	}

	var dbVersion int
	err = db.QueryRow("PRAGMA user_version;").Scan(&dbVersion)
	if err != nil {
		return fmt.Errorf("unable to get database version: %v", err)
	}

	for _, migration := range filesList {
		if !migration.IsDir() {
			contents, _ := files.ReadFile(migration.Name())
			lines := bytes.Split(contents, []byte("\n"))

			migrationVersion := parseMigrationFile(lines)

			if migrationVersion <= dbVersion {
				continue
			}

			log.Println("Running migration: ", migration.Name())

			transact, err := db.Begin()
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
