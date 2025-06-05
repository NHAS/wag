package data

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

func set[T any](key string, data T) (err error) {

	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal as json into etcd: %w", err)
	}

	_, err = etcd.Put(context.Background(), key, string(b))
	return
}

func get[T any](key string) (ret T, err error) {
	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return ret, err
	}

	if len(resp.Kvs) == 0 {
		return ret, fmt.Errorf("no %s keys", key)

	}

	if len(resp.Kvs) > 1 {
		return ret, fmt.Errorf("incorrect number of %s keys (>1)", key)
	}

	b := bytes.NewBuffer(resp.Kvs[0].Value)

	dec := json.NewDecoder(b)
	dec.DisallowUnknownFields()

	err = dec.Decode(&ret)
	if err != nil {
		return ret, err
	}

	return
}
