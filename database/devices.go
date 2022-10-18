package database

import (
	"database/sql"
	"net"
	"strconv"
	"strings"

	"github.com/NHAS/wag/utils"
)

type Device struct {
	Address   string
	Publickey string
	Username  string
	Enforcing bool
	Attempts  int
	Endpoint  *net.UDPAddr
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

func GetDevices() ([]Device, error) {

	rows, err := database.Query("SELECT address, publickey, username, endpoint, enforcing, attempts FROM Devices ORDER by ROWID DESC")
	if err != nil {
		return nil, err
	}

	result := []Device{}
	for rows.Next() {

		var (
			enforcing sql.NullString
			endpoint  sql.NullString
			d         Device
		)
		err = rows.Scan(&d.Address, &d.Publickey, &d.Username, &endpoint, &enforcing, &d.Attempts)
		if err != nil {
			return nil, err
		}

		if endpoint.Valid {
			d.Endpoint = stringToUDPaddr(endpoint.String)
		}

		d.Enforcing = enforcing.Valid

		result = append(result, d)
	}

	return result, nil

}

// Yes mildly cursed.
func GetDeviceByIP(address string) (d Device, err error) {
	return getDevice("address = ?", address)
}

func GetDeviceByUsername(username string) (d Device, err error) {
	return getDevice("username = ?", username)
}

func getDevice(attribute string, value string) (d Device, err error) {
	var (
		enforcing sql.NullString
		endpoint  sql.NullString
	)

	err = database.QueryRow("SELECT address, publickey, username, endpoint, enforcing, attempts FROM Devices WHERE "+attribute, value).Scan(&d.Address, &d.Publickey, &d.Username, &endpoint, &enforcing, &d.Attempts)
	if err != nil {
		return Device{}, err
	}

	if endpoint.Valid {
		d.Endpoint = stringToUDPaddr(endpoint.String)
	}

	d.Enforcing = enforcing.Valid

	return
}

func DeleteDevice(address string) error {
	_, err := database.Exec(`
		DELETE FROM
			Devices
		WHERE
			address = ?
	`, address)
	return err
}
