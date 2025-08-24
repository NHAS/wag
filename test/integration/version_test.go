package integration

import (
	"testing"

	"github.com/NHAS/wag/internal/config"
)

func TestGetVersion(t *testing.T) {

	version, err := ctrl.GetVersion()
	if err != nil {
		t.Fatal("should not error: ", err)
	}

	if version != config.Version {
		t.Fatal("values should be equal")
	}
}
