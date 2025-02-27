package mfaportal

type MFAMethod struct {
	Method       string `json:"method"`
	FriendlyName string `json:"friendly_name"`
}

type UserInfoDTO struct {
	Locked              bool        `json:"is_locked"`
	HelpMail            string      `json:"helpmail"`
	DefaultMFAMethod    string      `json:"default_mfa"`
	AvailableMfaMethods []MFAMethod `json:"available_mfa_methods"`
	Registered          bool        `json:"has_registered"`
	Username            string      `json:"username"`
	Authorised          bool        `json:"is_authorized"`
}

type StatusDTO struct {
	IsAuthorised bool

	MFA    []string
	Public []string
	Deny   []string
}

type ChallengeAuthorisationDTO struct {
	Challenge string `json:"challenge"`
}

type DeauthNotificationDTO struct {
	Status string `json:"status"`
}
