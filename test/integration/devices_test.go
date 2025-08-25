package integration

import (
	"slices"
	"testing"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAddDevice(t *testing.T) {

	const username = "test_made_user"
	user, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal(err)
	}

	k, _ := wgtypes.GenerateKey()
	err = ctrl.CreateDevice(control.CreateDeviceDTO{
		Username:  user.Username,
		Publickey: k.String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	devices, err := ctrl.ListDevice("")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.ContainsFunc(devices, func(d data.Device) bool {
		return d.Username == username && d.Publickey == k.String()
	}) {
		t.Fatal("device should be present in list of all devices")
	}

}

func TestAddDeviceWthoutUser(t *testing.T) {
	k, _ := wgtypes.GenerateKey()

	err := ctrl.CreateDevice(control.CreateDeviceDTO{
		Username:  "test_unmade_user",
		Publickey: k.String(),
	})
	if err == nil {
		t.Fatal("devices should not be unbound from users")
	}
}
