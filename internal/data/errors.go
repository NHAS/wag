package data

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
)

// RaiseError creates an entry in the etcd database that will be presented to the user as a notification
// Parameters:
//   - raisedError: The error text to present
//   - value: The data that caused the error
//
// Returns:
//   - error: Will error if it cannot generate a unique ID or add it to the etcd db
func (d *database) RaiseError(raisedError error, value []byte) {

	ee := config.EventError{
		NodeID:          d.GetCurrentNodeID().String(),
		FailedEventData: string(value),
		Error:           raisedError.Error(),
		Time:            time.Now(),
	}

	var err error
	ee.ErrorID, err = utils.GenerateRandomHex(16)
	if err != nil {
		log.Error().Err(err).Str("cluster_error", raisedError.Error()).Msg("failed to generate unique error ID")

		return
	}

	err = InternalConfig.Nodes.Errors().Key(ee.ErrorID).Put(context.Background(), d.etcd, ee)
	if err != nil {
		log.Error().Err(err).Str("cluster_error", raisedError.Error()).Msg("failed to write error to cluster")

		return
	}
}

func (d *database) GetAllErrors() (ret []config.EventError, err error) {
	return InternalConfig.Nodes.Errors().Entries(context.Background(), d.etcd)

}

func (d *database) ResolveError(errorId string) error {

	_, err := InternalConfig.Nodes.Errors().Key(errorId).Delete(context.Background(), d.etcd)
	return err
}
