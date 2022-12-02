package data

import (
	"database/sql"
	"errors"
	"time"

	"github.com/NHAS/wag/config"
	"github.com/pquerna/otp/totp"
)

type UserModel struct {
	Username  string
	Mfa       string
	Locked    bool
	Enforcing bool
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

func GetAuthenticationDetails(username, device string) (mfa string, attempts int, locked bool, err error) {

	err = database.QueryRow(`SELECT 
								mfa, attempts, locked 
							 FROM 
							 	Users 
							 INNER JOIN 
								Devices 
							 ON 
							 	Users.username = Devices.username 
							 WHERE 
							 	Devices.address = ? AND Users.username = ?`, device, username).Scan(&mfa, &attempts, &locked)
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
		Devices
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

func GetTOTPSecret(username string) (string, error) {
	var url string
	var enforcing sql.NullString
	err := database.QueryRow(`
		SELECT 
			mfa, enforcing 
		FROM 
			Users
		WHERE
			username = ?
	`, username).Scan(&url, &enforcing)
	if err != nil {
		return "", err
	}

	if enforcing.Valid {
		return "", errors.New("MFA is set to enforcing, cannot reveal secret.")
	}

	return url, nil
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
		username, mfa, locked, enforcing
	FROM 
		Users
	WHERE
		username = ?`, username).Scan(&u.Username, &u.Mfa, &u.Locked, &enforcing)
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

func SetUserMfa(username string) error {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.Values().Issuer,
		AccountName: username,
	})

	if err != nil {
		return err
	}

	_, err = database.Exec(`
	UPDATE 
		Users
	SET
		mfa = ?
	WHERE
		username = ?
	`, key.URL(), username)

	return err
}

func CreateUserDataAccount(username string) (UserModel, error) {

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.Values().Issuer,
		AccountName: username,
	})
	if err != nil {
		return UserModel{}, err
	}

	//Leaves enforcing null
	_, err = database.Exec(`
	INSERT INTO
		Users (username, mfa)
	VALUES
		(?, ?)
`, username, key.URL())

	return UserModel{
		Username: username,
		Mfa:      key.URL(),
	}, err

}

func GetAllUsers() (users []UserModel, err error) {

	rows, err := database.Query("SELECT username, mfa, enforcing, locked FROM Users ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			enforcing sql.NullString
			u         UserModel
		)
		err = rows.Scan(&u.Username, &u.Mfa, &enforcing, &u.Locked)
		if err != nil {
			return nil, err
		}

		u.Enforcing = enforcing.Valid

		users = append(users, u)
	}

	return users, nil

}
