package safedecoder

import (
	"encoding/json"
	"io"
)

func Decoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	return dec
}
