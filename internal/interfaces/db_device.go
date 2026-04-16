package interfaces

import (
	"net"

	"github.com/NHAS/wag/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceReader interface {
	GetDevice(username, id string) (device config.Device, err error)
	GetDevicesByUser(username string) (devices []config.Device, err error)
	GetAllDevices() (devices []config.Device, err error)
	GetDeviceByAddress(address string) (device config.Device, err error)
}

type DeviceWriter interface {
	AddDevice(username, publickey, staticIp, tag string) (config.Device, error)

	DeleteDevice(id string) error
	DeleteDevices(username string) error

	UpdateDeviceConnectionDetails(address string, endpoint *net.UDPAddr) error
	UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error
}

type DeviceRepository interface {
	DeviceReader
	DeviceWriter
}
