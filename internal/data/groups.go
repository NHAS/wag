package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/exp/maps"
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

	err = doSafeUpdate(context.Background(), "wag-membership", func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("bad number of membership keys")
		}

		var rGroupLookup map[string]map[string]bool
		err = json.Unmarshal(gr.Kvs[0].Value, &rGroupLookup)
		if err != nil {
			return "", err
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

		return string(reverseMappingJson), nil
	})

	return err
}

func GetGroups() (result []control.GroupData, err error) {

	resp, err := etcd.Get(context.Background(), "wag-groups-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, r := range resp.Kvs {

		var groupMembers []string
		err := json.Unmarshal(r.Value, &groupMembers)
		if err != nil {
			return nil, err
		}

		result = append(result, control.GroupData{
			Group:   string(bytes.TrimPrefix(r.Key, []byte("wag-groups-"))),
			Members: groupMembers,
		})
	}

	return
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

	err = doSafeUpdate(context.Background(), "wag-membership", func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("bad number of membership keys")
		}

		var rGroupLookup map[string]map[string]bool
		err = json.Unmarshal(gr.Kvs[0].Value, &rGroupLookup)
		if err != nil {
			return "", err
		}

		for _, member := range oldMembers {
			delete(rGroupLookup[member], groupName)
		}

		reverseMappingJson, _ := json.Marshal(rGroupLookup)

		return string(reverseMappingJson), nil
	})

	return err
}

func GetUserGroupMembership(username string) ([]string, error) {

	response, err := etcd.Get(context.Background(), "wag-membership")
	if err != nil {
		return nil, err
	}

	var rGroupLookup map[string]map[string]bool

	err = json.Unmarshal(response.Kvs[0].Value, &rGroupLookup)
	if err != nil {
		return nil, err
	}

	if rGroupLookup[username] == nil {
		return []string{}, nil
	}

	return maps.Keys(rGroupLookup[username]), nil
}

func SetUserGroupMembership(username string, newGroups []string) error {

	err := doSafeUpdate(context.Background(), "wag-membership", func(gr *clientv3.GetResponse) (value string, err error) {

		if len(gr.Kvs) != 1 {
			return "", errors.New("bad number of membership keys")
		}

		var rGroupLookup map[string]map[string]bool
		err = json.Unmarshal(gr.Kvs[0].Value, &rGroupLookup)
		if err != nil {
			return "", err
		}

		groups := map[string]bool{}
		for _, group := range newGroups {
			groups[group] = true
		}

		rGroupLookup[username] = groups

		reverseMappingJson, _ := json.Marshal(rGroupLookup)

		return string(reverseMappingJson), nil
	})

	return err
}
