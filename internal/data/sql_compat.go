package data

import (
	"database/sql"
	"encoding/json"

	"github.com/NHAS/wag/pkg/control"
)

func sqlgetAllAdminUsers() (adminUsers []admin, err error) {

	rows, err := database.Query("SELECT username, passwd_hash, attempts, last_login, ip, date_added, change FROM AdminUsers ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			LastLogin sql.NullString
			IP        sql.NullString
			au        admin
		)
		err = rows.Scan(&au.Username, &au.Hash, &au.Attempts, &LastLogin, &IP, &au.DateAdded, &au.Change)
		if err != nil {
			return nil, err
		}

		au.LastLogin = LastLogin.String
		au.IP = IP.String

		adminUsers = append(adminUsers, au)
	}

	return adminUsers, nil

}

func sqlGetAllUsers() (users []UserModel, err error) {

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

func sqlGetRegistrationTokens() (result []control.RegistrationResult, err error) {

	rows, err := database.Query("SELECT token, username, overwrite, groups, uses FROM RegistrationTokens ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var (
			groupsJson   sql.NullString
			registration control.RegistrationResult
		)
		err = rows.Scan(&registration.Token, &registration.Username, &registration.Overwrites, &groupsJson, &registration.NumUses)
		if err != nil {
			return nil, err
		}

		if groupsJson.Valid {
			err = json.Unmarshal([]byte(groupsJson.String), &registration.Groups)
			if err != nil {
				return
			}
		}

		result = append(result, registration)
	}

	return result, nil
}

func sqlGetAllDevices() (devices []Device, err error) {
	rows, err := database.Query("SELECT address, publickey, username, endpoint, attempts, preshared_key FROM Devices ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			endpoint sql.NullString
			d        Device
		)
		err = rows.Scan(&d.Address, &d.Publickey, &d.Username, &endpoint, &d.Attempts, &d.PresharedKey)
		if err != nil {
			return nil, err
		}

		if endpoint.Valid {
			d.Endpoint = stringToUDPaddr(endpoint.String)
		}

		devices = append(devices, d)
	}

	return devices, nil
}