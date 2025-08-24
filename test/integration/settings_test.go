package integration

import "testing"

func TestLoginSettings(t *testing.T) {
	loginSettings, err := ctrl.GetLoginSettings()
	if err != nil {
		t.Fatal("should be able to get login settings: ", err)
	}

	err = ctrl.SetLoginSettings(loginSettings)
	if err != nil {
		t.Fatal("should be able to set login settings: ", err)
	}

}

func TestSetInvalidLoginSettings(t *testing.T) {
	loginSettings, err := ctrl.GetLoginSettings()
	if err != nil {
		t.Fatal("should be able to get login settings: ", err)
	}

	loginSettingsCopy := loginSettings

	loginSettingsCopy.DefaultMFAMethod = "wombo"
	err = ctrl.SetLoginSettings(loginSettingsCopy)
	if err == nil {
		t.Fatal("should not be able to set a made up mfa method")
	}

	loginSettingsCopy = loginSettings
	loginSettingsCopy.EnabledMFAMethods = []string{
		"wambo",
	}
	err = ctrl.SetLoginSettings(loginSettingsCopy)
	if err == nil {
		t.Fatal("should not be able to enable made up mfa methods")
	}

	loginSettingsCopy = loginSettings
	loginSettingsCopy.OidcDetails.IssuerURL = "not_a_url"
	err = ctrl.SetLoginSettings(loginSettingsCopy)
	if err == nil {
		t.Fatal("should not be able to set oidc url as something other than a url")
	}

}

func TestGeneralSettings(t *testing.T) {
	generalSettings, err := ctrl.GetGeneralSettings()
	if err != nil {
		t.Fatal("should be able to get general settings: ", err)
	}

	err = ctrl.SetGeneralSettings(generalSettings)
	if err != nil {
		t.Fatal("should be able to set general settings: ", err)
	}
}

func TestSetInvalidGeneralSettings(t *testing.T) {
	generalSettings, err := ctrl.GetGeneralSettings()
	if err != nil {
		t.Fatal("should be able to get general settings: ", err)
	}

	generalSettingsCopy := generalSettings
	generalSettingsCopy.HelpMail = "not_email_here"

	err = ctrl.SetGeneralSettings(generalSettingsCopy)
	if err == nil {
		t.Fatal("should not be able to set general settings email as anything other than an email")
	}

	generalSettingsCopy = generalSettings
	generalSettingsCopy.WireguardConfigFilename = ""

	err = ctrl.SetGeneralSettings(generalSettingsCopy)
	if err == nil {
		t.Fatal("shouldnt be able to set wireguard config download to nothing")
	}

	generalSettingsCopy = generalSettings
	generalSettingsCopy.DNS = []string{
		"",
	}

	err = ctrl.SetGeneralSettings(generalSettingsCopy)
	if err == nil {
		t.Fatal("shouldnt be able to set DNS to empty")
	}
}
