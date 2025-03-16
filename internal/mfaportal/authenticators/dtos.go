package authenticators

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/data"
)

type TOTPSecretDTO struct {
	ImageData   string `json:"image_data"`
	Key         string `json:"key"`
	AccountName string `json:"account_name"`
}

type TOTPRequestDTO struct {
	Code string `json:"code"`
}

type PAMRequestDTO struct {
	Password string `json:"password"`
}

type StatusType string

const (
	Success   StatusType = "success"
	Challenge StatusType = "challenge"
	Details   StatusType = "register_details"

	Error StatusType = "error"
)

type AuthResponse struct {
	Status StatusType  `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	w.WriteHeader(c)

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(d)
	if err != nil {
		log.Println("failed to write json: ", err)
	}

}

func resultMessage(err error) (string, int) {
	if err == nil {
		return "Success", http.StatusOK
	}

	mail := data.GetHelpMail()

	msg := "Validation failed"
	if strings.Contains(err.Error(), "account is locked") {
		msg = "Account is locked contact: " + mail
	} else if strings.Contains(err.Error(), "device is locked") {
		msg = "Device is locked contact: " + mail
	}
	return msg, http.StatusBadRequest
}
