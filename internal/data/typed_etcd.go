package data

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/NHAS/wag/pkg/safedecoder"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

func Set[T any](etcd *clientv3.Client, key string, overwrite bool, data T) (err error) {

	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal as json into etcd: %w", err)
	}

	if overwrite {

		_, err := etcd.Put(context.Background(), key, string(b))
		return err
	}

	txn := etcd.Txn(context.Background())
	txn.If(clientv3util.KeyMissing(key))
	txn.Then(clientv3.OpPut(key, string(b)))

	resp, err := txn.Commit()
	if err != nil {
		return err
	}

	if !resp.Succeeded {
		return fmt.Errorf("%q already exists, and overwrite = false", key)
	}

	return
}

func Get[T any](etcd *clientv3.Client, key string) (ret T, err error) {
	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return ret, err
	}

	if len(resp.Kvs) == 0 {
		return ret, fmt.Errorf("no data for %q ", key)

	}

	if len(resp.Kvs) > 1 {
		return ret, fmt.Errorf("incorrect number of values/keys  for %q (>1)", key)
	}

	b := bytes.NewBuffer(resp.Kvs[0].Value)

	dec := safedecoder.Decoder(b)
	dec.DisallowUnknownFields()

	err = dec.Decode(&ret)
	if err != nil {
		return ret, err
	}

	return
}
