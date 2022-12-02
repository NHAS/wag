package data

import (
	"database/sql"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/NHAS/wag/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Device struct {
	Address   string
	Publickey string
	Username  string
	Endpoint  *net.UDPAddr
	Attempts  int
}

func stringToUDPaddr(address string) (r *net.UDPAddr) {
	parts := strings.Split(address, ":")
	if len(parts) < 2 {
		return nil
	}

	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return nil
	}

	r = &net.UDPAddr{
		IP:   net.ParseIP(utils.GetIP(address)),
		Port: port,
	}

	return
}

func UpdateDeviceEndpoint(address string, endpoint *net.UDPAddr) error {

	_, err := database.Exec(`UPDATE Devices SET endpoint = ? WHERE address = ?`, endpoint.String(), address)
	if err != nil {
		return err
	}

	return nil
}

func GetDevice(username, id string) (device Device, err error) {
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
		username, id).Scan(&device.Address, &device.Username, &device.Publickey, &endpoint, &device.Attempts)

	if err != nil {
		return Device{}, err
	}

	if endpoint.Valid {
		device.Endpoint = stringToUDPaddr(endpoint.String)
	}

	return
}

func SetDeviceAuthenticationAttempts(username, address string, attempts int) error {
	_, err := database.Exec(`
	UPDATE 
		Devices
	SET
		attempts = ?
	WHERE
		address = ? AND username = ?
	`, attempts, address, username)

	if err != nil {
		return errors.New("Unable to set number of account attempts: " + err.Error())
	}

	return nil
}

func GetAllDevices() (devices []Device, err error) {

	rows, err := database.Query("SELECT address, publickey, username, endpoint, attempts FROM Devices ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	for rows.Next() {

		var (
			endpoint sql.NullString
			d        Device
		)
		err = rows.Scan(&d.Address, &d.Publickey, &d.Username, &endpoint, &d.Attempts)
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

func AddDevice(username, address, publickey string) (Device, error) {
	if net.ParseIP(address) == nil {
		return Device{}, errors.New("Address '" + address + "' cannot be parsed as IP, invalid")
	}

	//Leaves enforcing null
	_, err := database.Exec(`
	INSERT INTO
		Devices (address, username, publickey)
	VALUES
		(?, ?, ?)
`, address, username, publickey)

	return Device{
		Address:   address,
		Publickey: publickey,
		Username:  username,
	}, err
}

func DeleteDevice(username, id string) error {
	_, err := database.Exec(`
		DELETE FROM
			Devices
		WHERE
			username = ? AND 
			(address = $2 OR publickey = $2)
	`, username, id)
	return err
}

func DeleteDevices(username string) error {
	_, err := database.Exec(`
		DELETE FROM
			Devices
		WHERE
			username = ?
	`, username)
	return err
}

func UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error {
	_, err := database.Exec(`
		UPDATE
			Devices
		SET
		    publickey = ?
		WHERE
			username = ? AND address = ?`, publicKey.String(), username, address)
	return err
}

//CREATE TABLE Devices(address string primary key, username string not null, publickey string not null unique, endpoint string, attempts integer  DEFAULT 0 not null);

func GetDeviceByAddress(address string) (device Device, err error) {
	var (
		endpoint sql.NullString
	)

	err = database.QueryRow(`SELECT 
								* 
							FROM 
								Devices 
							WHERE 
								address = ?`,
		address).Scan(&device.Address, &device.Username, &device.Publickey, &endpoint, &device.Attempts)

	if err != nil {
		return Device{}, err
	}

	if endpoint.Valid {
		device.Endpoint = stringToUDPaddr(endpoint.String)
	}

	return
}

func GetDevicesByUser(username string) (devices []Device, err error) {
	rows, err := database.Query(`SELECT * FROM Devices WHERE username = ?`, username)
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
		//username string not null, publickey string not null unique, endpoint string, attempts integer not null
		err = rows.Scan(&d.Address, &d.Username, &d.Publickey, &endpoint, &d.Attempts)
		if err != nil {
			return nil, err
		}

		if endpoint.Valid {
			d.Endpoint = stringToUDPaddr(endpoint.String)
		}

		devices = append(devices, d)
	}

	return devices, rows.Err()
}
