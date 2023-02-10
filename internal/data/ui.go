package data

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

type AdminModel struct {
	Username  string `json:"username"`
	Attempts  int    `json:"attempts"`
	DateAdded string `json:"date_added"`
	LastLogin string `json:"last_login"`
	IP        string `json:"ip"`
}

func generateSalt() ([]byte, error) {
	randomData := make([]byte, 16)
	_, err := rand.Read(randomData)
	if err != nil {
		return nil, err
	}

	return randomData, nil
}

func CreateAdminUser(username, password string) error {
	if len(password) < 16 {
		return errors.New("password is too short for administrative console (passwords must be greater than 16 characters)")
	}

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

	_, err = database.Exec(`
	INSERT INTO
		AdminUsers (username, passwd_hash, date_added)
	VALUES
		(?,?,?)
`, username, base64.RawStdEncoding.EncodeToString(append(hash, salt...)), time.Now().Format(time.RFC3339))

	return err
}

func CompareAdminKeys(username, password string) error {

	// Do increment of attempts first to stop race conditions
	_, err := database.Exec(`UPDATE 
	AdminUsers 
	SET 
		attempts = attempts + 1 
	WHERE 
		attempts <= ? AND username = ?`,
		5, username)
	if err != nil {
		return err
	}

	var (
		attempts            int
		b64PasswordHashSalt string
	)
	err = database.QueryRow(`
	SELECT 
		passwd_hash, attempts
	FROM 
		AdminUsers
	WHERE
		username = ?
`, username).Scan(&b64PasswordHashSalt, &attempts)
	if err != nil {
		return err
	}

	rawHashSalt, err := base64.RawStdEncoding.DecodeString(b64PasswordHashSalt)
	if err != nil {
		return err
	}

	thisHash := argon2.IDKey([]byte(password), rawHashSalt[len(rawHashSalt)-16:], 1, 10*1024, 4, 32)

	if subtle.ConstantTimeCompare(thisHash, rawHashSalt[:len(rawHashSalt)-16]) != 1 {
		return errors.New("passwords did not match")
	}

	if attempts > 5 {
		return errors.New("account locked")
	}

	return nil
}

// Lock admin account and make them unable to login
func SetAdminUserLock(username string) error {

	_, err := database.Exec(`
	UPDATE 
		AdminUsers
	SET
		attempts = ?
	WHERE
		username = ?
	`, 6, username)

	if err != nil {
		return errors.New("Unable to lock admin account: " + err.Error())
	}

	return nil
}

// Unlock admin account
func SetAdminUserUnlock(username string) error {
	_, err := database.Exec(`
	UPDATE 
		AdminUsers
	SET
		attempts = ?
	WHERE
		username = ?
	`, 0, username)

	if err != nil {
		return errors.New("Unable to unlock admin account: " + err.Error())
	}

	return nil
}

func DeleteAdminUser(username string) error {

	_, err := database.Exec(`
		DELETE FROM
			AdminUsers
		WHERE
			username = ?`, username)
	if err != nil {
		return err
	}

	return err
}

func GetAdminUser(username string) (a AdminModel, err error) {

	var (
		LastLogin sql.NullString
		IP        sql.NullString
	)

	err = database.QueryRow(`
	SELECT 
		username, attempts, last_login, ip, date_added
	FROM 
		AdminUsers
	WHERE
		username = ?`, username).Scan(&a.Username, &a.Attempts, &LastLogin, &IP, &a.DateAdded)
	if err != nil {
		return
	}

	a.LastLogin = LastLogin.String
	a.IP = IP.String

	return
}

func GetAllAdminUsers() (adminUsers []AdminModel, err error) {

	rows, err := database.Query("SELECT username, attempts, last_login, ip, date_added FROM AdminUsers ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			LastLogin sql.NullString
			IP        sql.NullString
			au        AdminModel
		)
		err = rows.Scan(&au.Username, &au.Attempts, &LastLogin, &IP, &au.DateAdded)
		if err != nil {
			return nil, err
		}

		au.LastLogin = LastLogin.String
		au.IP = IP.String

		adminUsers = append(adminUsers, au)
	}

	return adminUsers, nil

}

func SetAdminPassword(username, password string) error {
	if len(password) < 16 {
		return errors.New("password is too short for administrative console (passwords must be greater than 16 characters)")
	}

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 10*1024, 4, 32)

	_, err = database.Exec(`
	UPDATE 
		AdminUsers
	SET
		passwd_hash = ?
	WHERE
		username = ?
	`, base64.RawStdEncoding.EncodeToString(append(hash, salt...)), username)

	if err != nil {
		return errors.New("Unable to set admin password hash: " + err.Error())
	}

	return nil
}

func SetLastLoginInformation(username, ip string) error {
	_, err := database.Exec(`
	UPDATE 
		AdminUsers
	SET
		last_login = ?,
		ip = ?
	WHERE
		username = ?
	`, time.Now().Format(time.RFC3339), ip, username)

	if err != nil {
		return errors.New("Unable to set last login time: " + err.Error())
	}

	return nil
}
