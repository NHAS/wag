package integration

import "testing"

func TestInitialAdmins(t *testing.T) {
	admins, err := ctrl.ListAdminUsers("")
	if err != nil {
		t.Fatal(err)
	}

	if len(admins) < 1 {
		t.Fatal("wag should always generate at least 1 admin")
	}

	adminDTO, err := ctrl.GetAdminUser(admins[0].Username)
	if err != nil {
		t.Fatal("should be able to query single admin user: ", err)
	}

	if adminDTO.DateAdded != admins[0].DateAdded {
		t.Fatal("admins should be the same: ", adminDTO, admins[0])
	}
}
