package interfaces

import (
	"net"

	"github.com/NHAS/wag/internal/data"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceReader interface {
	GetDevice(username, id string) (device data.Device, err error)
	GetDevicesByUser(username string) (devices []data.Device, err error)
	GetAllDevices() (devices []data.Device, err error)
	GetAllDevicesAsMap() (devices map[string]data.Device, err error)
	GetDeviceByAddress(address string) (device data.Device, err error)
}

type DeviceWriter interface {
	AddDevice(username, publickey, staticIp, tag string) (data.Device, error)

	DeleteDevice(id string) error
	DeleteDevices(username string) error

	UpdateDeviceConnectionDetails(address string, endpoint *net.UDPAddr) error
	UpdateDevicePublicKey(username, address string, publicKey wgtypes.Key) error
}

type DeviceRepository interface {
	DeviceReader
	DeviceWriter
}
