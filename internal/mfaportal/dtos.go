package mfaportal

type Status string

const (
	EndpointChallenge Status = "endpoint-change-challenge"
	Deauthed          Status = "deauthed"
	Authorised        Status = "authorised"
	PingType          Status = "ping"
)

type MFAMethod struct {
	Method       string `json:"method"`
	FriendlyName string `json:"friendly_name"`
}

type UserInfoDTO struct {
	Type                string      `json:"type"`
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

type NotificationDTO struct {
	Type Status `json:"type"`
}

func Challenge() NotificationDTO {
	return NotificationDTO{
		Type: EndpointChallenge,
	}
}

func AuthoriseSuccess() NotificationDTO {
	return NotificationDTO{
		Type: Authorised,
	}
}

func Deauth() NotificationDTO {
	return NotificationDTO{
		Type: Deauthed,
	}
}

func Ping() NotificationDTO {
	return NotificationDTO{
		Type: PingType,
	}
}

type PingResponseDTO struct {
	Pong string `json:"pong"`
}

type ChallengeResponseDTO struct {
	Challenge string `json:"challenge"`
}
