package database

import "database/sql"

type Device struct {
	Publickey, Username string
	Enforcing           bool
	Attempts            int
}

func GetDevices() (map[string]Device, error) {

	rows, err := database.Query("SELECT address, publickey, username, enforcing, attempts FROM Totp ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	result := make(map[string]Device)
	for rows.Next() {
		var address string
		var enforcing sql.NullString

		var d Device

		err = rows.Scan(&address, &d.Publickey, &d.Username, &enforcing, &d.Attempts)
		if err != nil {
			return nil, err
		}

		d.Enforcing = enforcing.Valid

		result[address] = d
	}

	return result, nil

}

func DeleteDevice(address string) error {
	_, err := database.Exec(`
		DELETE FROM
			Totp
		WHERE
			address = ?
	`, address)
	return err
}
