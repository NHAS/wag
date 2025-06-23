package data

import (
	"context"
	"encoding/json"
	"path"
	"time"

	"github.com/NHAS/wag/internal/utils"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type EventError struct {
	NodeID          string    `json:"node_id"`
	ErrorID         string    `json:"error_id"`
	FailedEventData string    `json:"failed_event_data"`
	Error           string    `json:"error"`
	Time            time.Time `json:"time"`
}

// RaiseError creates an entry in the etcd database that will be presented to the user as a notification
// Parameters:
//   - raisedError: The error text to present
//   - value: The data that caused the error
//
// Returns:
//   - error: Will error if it cannot generate a unique ID or add it to the etcd db
func (d *database) RaiseError(raisedError error, value []byte) (err error) {

	ee := EventError{
		NodeID:          d.GetCurrentNodeID().String(),
		FailedEventData: string(value),
		Error:           raisedError.Error(),
		Time:            time.Now(),
	}

	ee.ErrorID, err = utils.GenerateRandomHex(16)
	if err != nil {
		return err
	}

	return set(d.etcd, path.Join(NodeErrors, ee.ErrorID), false, ee)

}

func (d *database) GetAllErrors() (ret []EventError, err error) {
	response, err := d.etcd.Get(context.Background(), path.Join(NodeErrors), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var ee EventError
		err := json.Unmarshal(res.Value, &ee)
		if err != nil {
			return nil, err
		}

		ret = append(ret, ee)
	}

	return ret, nil
}

func (d *database) ResolveError(errorId string) error {
	_, err := d.etcd.Delete(context.Background(), path.Join(NodeErrors, errorId))
	return err
}
