package data

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

func generateSalt() ([]byte, error) {
	randomData := make([]byte, 16)
	_, err := rand.Read(randomData)
	if err != nil {
		return nil, err
	}

	return randomData, nil
}

func CreateAdminUser(username, password string) error {

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

	var b64PasswordHashSalt string
	err := database.QueryRow(`
	SELECT 
		passwd_hash
	FROM 
		AdminUsers
	WHERE
		username = ?
`, username).Scan(&b64PasswordHashSalt)
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

	return nil
}
