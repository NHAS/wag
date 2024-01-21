package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func SetGroup(group string, members []string, overwrite bool) error {
	response, err := etcd.Get(context.Background(), "wag-groups-"+group)
	if err != nil {
		return err
	}

	if len(response.Kvs) > 0 && !overwrite {
		return errors.New("group already exists")
	}

	membersJson, _ := json.Marshal(members)

	putResp, err := etcd.Put(context.Background(), "wag-groups-"+group, string(membersJson), clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	var oldMembers []string
	if putResp.PrevKv != nil {
		err = json.Unmarshal(putResp.PrevKv.Value, &oldMembers)
		if err != nil {
			return err
		}
	}

	err = doSafeUpdate(context.Background(), "wag-membership", func(gr *clientv3.GetResponse) (value string, onErrwrite bool, err error) {

		if len(gr.Kvs) != 1 {
			return "", false, errors.New("bad number of membership keys")
		}

		var rGroupLookup map[string]map[string]bool
		err = json.Unmarshal(gr.Kvs[0].Value, &rGroupLookup)
		if err != nil {
			return "", false, err
		}

		for _, member := range oldMembers {
			delete(rGroupLookup[member], group)
		}

		for _, member := range members {
			if rGroupLookup[member] == nil {
				rGroupLookup[member] = make(map[string]bool)
			}

			rGroupLookup[member][group] = true
		}

		reverseMappingJson, _ := json.Marshal(rGroupLookup)

		return string(reverseMappingJson), false, nil
	})

	return err

}

func RemoveGroup(groupName string) error {

	if groupName == "*" {
		return fmt.Errorf("cannot delete default group")
	}

	delResp, err := etcd.Delete(context.Background(), "wag-groups-"+groupName, clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	var oldMembers []string
	if len(delResp.PrevKvs) == 1 {
		err = json.Unmarshal(delResp.PrevKvs[0].Value, &oldMembers)
		if err != nil {
			return err
		}
	}

	err = doSafeUpdate(context.Background(), "wag-membership", func(gr *clientv3.GetResponse) (value string, onErrwrite bool, err error) {

		if len(gr.Kvs) != 1 {
			return "", false, errors.New("bad number of membership keys")
		}

		var rGroupLookup map[string]map[string]bool
		err = json.Unmarshal(gr.Kvs[0].Value, &rGroupLookup)
		if err != nil {
			return "", false, err
		}

		for _, member := range oldMembers {
			delete(rGroupLookup[member], groupName)
		}

		reverseMappingJson, _ := json.Marshal(rGroupLookup)

		return string(reverseMappingJson), false, nil
	})

	return err
}
