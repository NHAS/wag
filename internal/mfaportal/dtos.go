package mfaportal

import (
	"encoding/json"
	"net/http"
)

type MFAMethod struct {
	Method       string `json:"method"`
	FriendlyName string `json:"friendly_name"`
}

type UserInfoDTO struct {
	Locked              bool        `json:"is_locked"`
	HelpMail            string      `json:"helpmail"`
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

type GenericResponseDTO struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

func (mp *MfaPortal) respond(err error, w http.ResponseWriter) {

	var resp GenericResponseDTO
	resp.Success = true
	w.Header().Set("content-type", "application/json")
	resp.Message = "OK"
	if err != nil {
		resp.Success = false
		resp.Message = err.Error()
	}

	json.NewEncoder(w).Encode(resp)

}

func (mp *MfaPortal) respondSuccess(err error, success string, w http.ResponseWriter) {

	var resp GenericResponseDTO
	resp.Success = true
	w.Header().Set("content-type", "application/json")
	resp.Message = success
	if err != nil {
		resp.Success = false
		resp.Message = err.Error()
	}

	json.NewEncoder(w).Encode(resp)

}
