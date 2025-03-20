package mfaportal

import (
	"context"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type Status string

const (
	// To client
	Init              Status = "initialise"
	Info              Status = "info"
	EndpointChallenge Status = "endpoint-change-challenge"
	Authorised        Status = "authorised"

	PingType Status = "ping"

	// From client
	ChallengeResponse Status = "challenge-response"
	PongType          Status = "pong"
)

type MFAMethod struct {
	Method       string `json:"method"`
	FriendlyName string `json:"friendly_name"`
}

type UserInfoDTO struct {
	Type          Status `json:"type"`
	UserMFAMethod string `json:"user_mfa_method"`

	AccountLocked bool `json:"account_locked"`
	DeviceLocked  bool `json:"device_locked"`

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

type TypeDTO struct {
	Type Status `json:"type"`
}

func Challenge() TypeDTO {
	return TypeDTO{
		Type: EndpointChallenge,
	}
}

func AuthoriseSuccess() TypeDTO {
	return TypeDTO{
		Type: Authorised,
	}
}

type PongDTO struct {
	TypeDTO
	Pong bool `json:"pong"`
}

func Ping(conn *websocket.Conn, duration time.Duration) error {

	ctx, cancel := context.WithTimeout(context.Background(), duration/2)
	req := TypeDTO{
		Type: PingType,
	}
	err := wsjson.Write(ctx, conn, req)
	cancel()
	if err != nil {
		return err
	}

	ctx, cancel = context.WithTimeout(context.Background(), duration)
	res := PongDTO{}
	err = wsjson.Read(ctx, conn, &res)
	cancel()
	if err != nil {
		return err
	}

	if res.Type != PongType {
		return fmt.Errorf("client did not return pong type, got: %q", res.Type)
	}

	if !res.Pong {
		return fmt.Errorf("client returned false pong")
	}

	return nil
}

type ChallengeResponseDTO struct {
	TypeDTO
	Challenge string `json:"challenge"`
}

func ReadChallenge(conn *websocket.Conn, duration time.Duration) (ChallengeResponseDTO, error) {

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	var res ChallengeResponseDTO
	err := wsjson.Read(ctx, conn, &res)
	cancel()
	if err != nil {
		return ChallengeResponseDTO{}, fmt.Errorf("failed to read challenge: %w", err)
	}

	if res.Type != ChallengeResponse {
		return ChallengeResponseDTO{}, fmt.Errorf("client did not return challenge response type, got: %q", res.Type)
	}

	return res, nil
}

type AuthorisedDTO struct {
	TypeDTO
	AuthorisationTime time.Time   `json:"authorisation_time"`
	Info              UserInfoDTO `json:"info"`
	Challenge         string      `json:"challenge"`
}

func SendNotifyAuth(conn *websocket.Conn, challenge string, info UserInfoDTO, authTime time.Time, duration time.Duration) error {

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	res := AuthorisedDTO{
		AuthorisationTime: authTime,
		Challenge:         challenge,
		Info:              info,
	}
	res.Type = Authorised

	err := wsjson.Write(ctx, conn, res)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to write authorisation status: %w", err)
	}

	return nil
}
