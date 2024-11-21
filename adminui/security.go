package adminui

import (
	"encoding/json"
	"net/http"
)

func (au *AdminUI) respond(err error, w http.ResponseWriter) {

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
