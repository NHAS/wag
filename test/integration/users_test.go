package integration

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/pkg/control"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestApiUserCreation(t *testing.T) {

	const username = "test_user"

	user, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal("should be able to add user with fine name: ", err)
	}

	if user.Enforcing {
		t.Fatal("newly created users should not be enforcing mfa")
	}

	if user.MfaType != string(types.Unset) {
		t.Fatal("new users should have mfa unset")
	}

	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.ContainsFunc(allUsers, func(u data.UserModel) bool {
		return u.Username == username
	}) {
		t.Fatal("user should be part of all users list")
	}

	token := makeRegistrationToken()

	_, err = ctrl.NewRegistration(token, username, "", "", 1, "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + token)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("invalid status")
	}

	devices, err := ctrl.ListDevice(username)
	if err != nil {
		t.Fatal(err)
	}

	if len(devices) != 1 {
		t.Fatal("user should only have 1 device", devices)
	}
}

func TestTokenUserCreation(t *testing.T) {

	const username = "unique_222222"
	token := makeRegistrationToken()

	_, err := ctrl.NewRegistration(token, username, "", "", 1, "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get("http://127.0.0.1:8081/register_device?key=" + token)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("invalid status")
	}

	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.ContainsFunc(allUsers, func(u data.UserModel) bool {
		return u.Username == username
	}) {
		t.Fatal("user should be part of all users list")
	}

	devices, err := ctrl.ListDevice(username)
	if err != nil {
		t.Fatal(err)
	}

	if len(devices) != 1 {
		t.Fatal("user should only have 1 device", devices)
	}
}

func TestApiUserCreationInvalidNames(t *testing.T) {
	invalidUsernames := []string{
		"user-with-spaces",
		"",                        // empty string
		strings.Repeat("a", 1000), // very long username
	}

	for _, username := range invalidUsernames {
		t.Run(username, func(t *testing.T) {
			_, err := ctrl.AddUser(username)
			if err == nil {
				t.Fatalf("Should not be able to create user with username: %q", username)
			}
		})
	}
}

func TestDuplicateUserCreation(t *testing.T) {
	const username = "duplicate_test_user"

	// Create user first time
	_, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal("First user creation should succeed:", err)
	}

	// Attempt to create same user again
	_, err = ctrl.AddUser(username)
	if err == nil {
		t.Fatal("Should not be able to create duplicate user")
	}

	// Verify original user still exists and is unchanged
	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, u := range allUsers {
		if u.Username == username {
			found++
		}

		if found >= 2 {
			t.Fatal("two users should not exist")
		}
	}

}

func TestLockAndUnlock(t *testing.T) {
	const username = "lock_user_test"

	user, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal("creation should succeed:", err)
	}

	err = ctrl.LockUser(user.Username)
	if err != nil {
		t.Fatal(err)
	}

	users, err := ctrl.ListUsers(user.Username)
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 1 {
		t.Fatal("selecting single user should result in one user")
	}

	if !users[0].Locked {
		t.Fatal("after lock user should be locked")
	}

	err = ctrl.UnlockUser(user.Username)
	if err != nil {
		t.Fatal(err)
	}

	users, err = ctrl.ListUsers(user.Username)
	if err != nil {
		t.Fatal(err)
	}

	if users[0].Locked {
		t.Fatal("after lock user should be unlocked")
	}
}

func TestGetUserAcls(t *testing.T) {
	const username = "acls_test"

	user, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal("creation should succeed:", err)
	}

	_, err = ctrl.GetUsersAcls(user.Username)
	if err != nil {
		t.Fatal(err)
	}

}

func TestDeleteUser(t *testing.T) {
	const username = "delete_test"

	user, err := ctrl.AddUser(username)
	if err != nil {
		t.Fatal("creation should succeed:", err)
	}

	k, _ := wgtypes.GenerateKey()
	err = ctrl.CreateDevice(control.CreateDeviceDTO{
		Username:  username,
		Publickey: k.String(),
	})
	if err != nil {
		t.Fatal("failed to add device to new user: ", err)
	}

	err = ctrl.DeleteUser(user.Username)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ctrl.ListUsers(username)
	if err == nil {
		t.Fatal("user should no longer exist")
	}

	devices, err := ctrl.ListDevice("")
	if err != nil {
		t.Fatal(err)
	}

	if slices.ContainsFunc(devices, func(d data.Device) bool {
		return d.Username == username
	}) {
		t.Fatal("device should not still be present after user delete")
	}

}
