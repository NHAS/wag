package data

import (
	"crypto/sha1"
	"database/sql"
	"errors"
	"time"

	"github.com/NHAS/wag/internal/config"
)

type UserModel struct {
	Username  string
	Mfa       string
	MfaType   string
	Locked    bool
	Enforcing bool
}

func (um *UserModel) GetID() [20]byte {
	return sha1.Sum([]byte(um.Username))
}

// Make sure that the attempts is always incremented first to stop race condition attacks
func IncrementAuthenticationAttempt(username, device string) error {
	_, err := database.Exec(`UPDATE 
		Devices 
	SET 
		attempts = attempts + 1 
	WHERE 
		address = ? AND attempts <= ? AND username = ?`,
		device, config.Values().Lockout, username)
	if err != nil {
		return err
	}

	return nil
}

func GetAuthenticationDetails(username, device string) (mfa, mfaType string, attempts int, locked bool, err error) {

	err = database.QueryRow(`SELECT 
								mfa, mfa_type, attempts, locked 
							 FROM 
							 	Users 
							 INNER JOIN 
								Devices 
							 ON 
							 	Users.username = Devices.username 
							 WHERE 
							 	Devices.address = ? AND Users.username = ?`, device, username).Scan(&mfa, &mfaType, &attempts, &locked)
	if err != nil {
		return
	}

	return
}

// Disable authentication for user
func SetUserLock(username string) error {

	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		locked = ?
	WHERE
		username = ?
	`, true, username)

	if err != nil {
		return errors.New("Unable to lock account: " + err.Error())
	}

	return nil
}

func SetUserUnlock(username string) error {
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		locked = ?
	WHERE
		username = ?
	`, false, username)

	if err != nil {
		return errors.New("Unable to unlock account: " + err.Error())
	}

	return nil
}

// Has the user recorded their MFA details. Always read the latest value from the DB
func IsEnforcingMFA(username string) bool {
	var enforcing sql.NullString
	err := database.QueryRow(`
	SELECT 
		enforcing 
	FROM 
		Users
	WHERE
		username = ?
`, username).Scan(&enforcing)

	// Fail closed
	if err != nil {
		return true
	}

	return enforcing.Valid
}

// Stop displaying MFA secrets for user
func SetEnforceMFAOn(username string) error {
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		enforcing = ?
	WHERE
		username = ?
	`, time.Now().Format(time.RFC3339), username)

	return err
}

func SetEnforceMFAOff(username string) error {
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		enforcing = ?
	WHERE
		username = ?
	`, nil, username)

	return err
}

func GetMFASecret(username string) (string, error) {
	var (
		url, mfaType string
		enforcing    sql.NullString
	)
	err := database.QueryRow(`
		SELECT 
			mfa, mfa_type, enforcing 
		FROM 
			Users
		WHERE
			username = ?
	`, username).Scan(&url, &mfaType, &enforcing)
	if err != nil {
		return "", err
	}

	// The webauthn "secret" needs to be used, but isnt returned to the client
	if enforcing.Valid && mfaType != "webauthn" {
		return "", errors.New("MFA is set to enforcing, cannot reveal totp secret.")
	}

	return url, nil
}

func GetMFAType(username string) (string, error) {
	var (
		mfaType string
	)
	err := database.QueryRow(`
		SELECT 
			mfa_type 
		FROM 
			Users
		WHERE
			username = ?
	`, username).Scan(&mfaType)
	if err != nil {
		return "", err
	}

	return mfaType, nil
}

func DeleteUser(username string) error {

	_, err := database.Exec(`
		DELETE FROM
			Users
		WHERE
			username = ?`, username)
	if err != nil {
		return err
	}

	_, err = database.Exec(`
		DELETE FROM
			Devices
		WHERE
			username = ?`, username)

	return err
}

func GetUserData(username string) (u UserModel, err error) {

	var enforcing sql.NullString

	err = database.QueryRow(`
	SELECT 
		username, mfa, mfa_type, locked, enforcing
	FROM 
		Users
	WHERE
		username = ?`, username).Scan(&u.Username, &u.Mfa, &u.MfaType, &u.Locked, &enforcing)
	if err != nil {
		return UserModel{}, err
	}

	u.Enforcing = enforcing.Valid

	return
}

func GetUserDataFromAddress(address string) (u UserModel, err error) {

	var username string
	err = database.QueryRow(`
	SELECT 
		username 
	FROM 
		Devices
	WHERE
		address = ?`, address).Scan(&username)
	if err != nil {
		return
	}

	return GetUserData(username)
}

func SetUserMfa(username, value, mfaType string) error {

	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		mfa = ?, mfa_type = ?
	WHERE
		username = ?
	`, value, mfaType, username)

	return err
}

func CreateUserDataAccount(username string) (UserModel, error) {

	//Leaves enforcing null
	_, err := database.Exec(`
	INSERT INTO
		Users (username,mfa)
	VALUES
		(?,"")
`, username)

	return UserModel{
		Username: username,
	}, err
}

func GetAllUsers() (users []UserModel, err error) {

	rows, err := database.Query("SELECT username, mfa, mfa_type, enforcing, locked FROM Users ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			enforcing sql.NullString
			u         UserModel
		)
		err = rows.Scan(&u.Username, &u.Mfa, &u.MfaType, &enforcing, &u.Locked)
		if err != nil {
			return nil, err
		}

		u.Enforcing = enforcing.Valid

		users = append(users, u)
	}

	return users, nil

}
