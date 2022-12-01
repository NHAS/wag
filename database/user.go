package database

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/NHAS/wag/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type user struct {
	Username string
	Mfa      string
	Locked   bool
}

func (u *user) GetDevice(id string) (device Device, err error) {
	var (
		endpoint sql.NullString
	)

	err = database.QueryRow(`SELECT 
								* 
							FROM 
								Devices 
							WHERE 
								username = ? 
									AND 
								(address = $2 OR publickey = $2)`,
		u.Username, id).Scan(&device.Address, &device.Username, &device.Publickey, &endpoint)

	if err != nil {
		return Device{}, err
	}

	if endpoint.Valid {
		device.Endpoint = stringToUDPaddr(endpoint.String)
	}

	return
}

func (u *user) GetDevices() (devices []Device, err error) {
	rows, err := database.Query(`SELECT * FROM Devices WHERE username = ?`, u.Username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {

		var (
			endpoint sql.NullString
		)

		var d Device
		//Devices(address string primary key,
		//username string not null, publickey string not null unique, endpoint string, attempts integer not null );
		err = rows.Scan(&d.Address, &d.Username, &d.Publickey, &endpoint, &d.Attempts)
		if err != nil {
			return nil, err
		}

		if endpoint.Valid {
			d.Endpoint = stringToUDPaddr(endpoint.String)
		}

		devices = append(devices, d)
	}

	return nil, rows.Err()
}

type entry struct {
	usetime time.Time
	code    string
}

// Make sure that one time passwords (OTPs) are truly one time, store used codes
var lockULock sync.Mutex
var usedCodes = map[string]entry{}

func (u *user) Authenticate(address, code string) (err error) {

	// Make sure that the device belongs to this user
	var m string
	err = database.QueryRow(`SELECT 
								address 
							FROM 
								Devices 
							WHERE 
								address = ? AND username = ?`, address, u.Username).Scan(&m)
	if err != nil {
		return errors.New("failed to get device to authorise for user: " + u.Username + err.Error())
	}

	// Make sure that the attempts is always incremented first to stop race condition attacks
	_, err = database.Exec(`UPDATE 
								Devices 
							SET 
								attempts = attempts + 1 
							WHERE 
								address = ? AND attempts <= ? AND username = ?`,
		address, config.Values().Lockout, u.Username)
	if err != nil {
		return
	}

	var (
		mfa      string
		attempts int
		locked   bool
	)
	err = database.QueryRow(`SELECT 
								mfa, attempts, locked 
							 FROM 
							 	Users 
							 INNER JOIN 
								Devices 
							 ON 
							 	Users.username = Devices.username 
							 WHERE 
							 	Devices.address = ? AND username = ?`, address, u.Username).Scan(&mfa, &attempts, &locked)
	if err != nil {
		return
	}

	if attempts > config.Values().Lockout || locked {
		return errors.New("account is locked")
	}

	key, err := otp.NewKeyFromURL(mfa)
	if err != nil {
		return
	}

	if !totp.Validate(code, key.Secret()) {
		return errors.New("code does not match expected")
	}

	lockULock.Lock()

	e := usedCodes[u.Username]
	if e.code == code && e.usetime.Add(30*time.Second).After(time.Now()) {
		return errors.New("code already used")
	}

	usedCodes[u.Username] = entry{code: code, usetime: time.Now()}
	lockULock.Unlock()

	return
}

func (u *user) SetDeviceAuthenticationAttempts(address string, attempts int) error {
	_, err := database.Exec(`
	UPDATE 
		Devices
	SET
		attempts = ?
	WHERE
		address = ? AND username = ?
	`, attempts, address, u.Username)

	if err != nil {
		return errors.New("Unable to set number of account attempts: " + err.Error())
	}

	return nil
}

// Disable authentication for user
func (u *user) Lock() error {
	u.Locked = true
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		locked = ?
	WHERE
		username = ?
	`, true, u.Username)

	if err != nil {
		return errors.New("Unable to lock account: " + err.Error())
	}

	return nil
}

func (u *user) Unlock() error {
	u.Locked = false
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		locked = ?
	WHERE
		username = ?
	`, false, u.Username)

	if err != nil {
		return errors.New("Unable to unlock account: " + err.Error())
	}

	return nil
}

// Has the user recorded their MFA details. Always read the latest value from the DB
func (u *user) IsEnforcingMFA() bool {
	var enforcing sql.NullString
	err := database.QueryRow(`
	SELECT 
		enforcing 
	FROM 
		Devices
	WHERE
		username = ?
`, u.Username).Scan(&enforcing)

	// Fail closed
	if err != nil {
		return true
	}

	return enforcing.Valid
}

// Stop displaying MFA secrets for user
func (u *user) SetEnforceMFAOn() error {
	_, err := database.Exec(`
	UPDATE 
		Users
	SET
		enforcing = ?
	WHERE
		username = ?
	`, time.Now().Format(time.RFC3339), u.Username)

	return err
}

func (u *user) ShowTOTPSecret() (*otp.Key, error) {
	var url string
	var enforcing sql.NullString
	err := database.QueryRow(`
		SELECT 
			mfa, enforcing 
		FROM 
			Users
		WHERE
			username = ?
	`, u.Username).Scan(&url, &enforcing)
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

func GetUser(username string) (u user, err error) {

	err = database.QueryRow(`
	SELECT 
		(username, mfa, locked) 
	FROM 
		Users
	WHERE
		username = ?`, username).Scan(&u.Username, &u.Mfa, &u.Locked)

	return user{}, err
}

func GetUserFromAddress(address string) (u user, err error) {

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

	return GetUser(address)
}

func CreateUserAccount(username string) (user, error) {

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.Values().Issuer,
		AccountName: username,
	})
	if err != nil {
		return user{}, err
	}

	//Leaves enforcing null
	_, err = database.Exec(`
	INSERT INTO
		Users (username, mfa)
	VALUES
		(?, ?)
`, username, key.URL())

	return user{
		Username: username,
		Mfa:      key.URL(),
	}, err

}
