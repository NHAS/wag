package database

import "database/sql"

type Device struct {
	Address   string
	Publickey string
	Username  string
	Enforcing bool
	Attempts  int
}

func GetDevices() ([]Device, error) {

	rows, err := database.Query("SELECT address, publickey, username, enforcing, attempts FROM Totp ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	result := []Device{}
	for rows.Next() {

		var enforcing sql.NullString
		var d Device

		err = rows.Scan(&d.Address, &d.Publickey, &d.Username, &enforcing, &d.Attempts)
		if err != nil {
			return nil, err
		}

		d.Enforcing = enforcing.Valid

		result = append(result, d)
	}

	return result, nil

}

func GetDeviceByIP(address string) (d Device, err error) {
	var enforcing sql.NullString
	err = database.QueryRow("SELECT address, publickey, username, enforcing, attempts FROM Totp WHERE address = ?", address).Scan(&d.Address, &d.Publickey, &d.Username, &enforcing, &d.Attempts)
	if err != nil {
		return Device{}, err
	}

	d.Enforcing = enforcing.Valid

	return
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
