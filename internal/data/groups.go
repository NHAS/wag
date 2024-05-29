package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func SetGroup(group string, members []string, overwrite bool) error {
	response, err := etcd.Get(context.Background(), GroupsPrefix+group)
	if err != nil {
		return err
	}

	if len(response.Kvs) > 0 && !overwrite {
		return errors.New("group already exists")
	}

	membersJson, _ := json.Marshal(members)

	putResp, err := etcd.Put(context.Background(), GroupsPrefix+group, string(membersJson), clientv3.WithPrevKV())
	if err != nil {
		return err
	}

	var existingMembers []string
	if putResp.PrevKv != nil {
		err = json.Unmarshal(putResp.PrevKv.Value, &existingMembers)
		if err != nil {
			return err
		}
	}

	currentMembers := map[string]bool{}
	for _, member := range members {
		currentMembers[member] = true
	}

	removedMembers := []string{}
	previousMembers := map[string]bool{}
	for _, member := range existingMembers {
		if !currentMembers[member] {
			removedMembers = append(removedMembers, member)
		}
		previousMembers[member] = true
	}

	addedMembers := []string{}
	for _, member := range members {
		if previousMembers[member] {
			continue
		}

		addedMembers = append(addedMembers, member)
	}

	var errs []error
	for _, member := range addedMembers {
		err = doSafeUpdate(context.Background(), MembershipKey+"-"+member, true, func(gr *clientv3.GetResponse) (value string, err error) {

			var memberCurrentGroups []string

			if len(gr.Kvs) > 1 {
				return "", fmt.Errorf("bad number of membership keys: %d", len(gr.Kvs))
			}

			if len(gr.Kvs) == 1 {
				err = json.Unmarshal(gr.Kvs[0].Value, &memberCurrentGroups)
				if err != nil {
					return "", err
				}
			}

			if slices.Index(memberCurrentGroups, group) == -1 {
				memberCurrentGroups = append(memberCurrentGroups, group)
			}

			reverseMappingJson, _ := json.Marshal(memberCurrentGroups)

			return string(reverseMappingJson), nil
		})
		if err != nil {
			log.Println("failed to add member ", member, "to group: ", err)
			errs = append(errs, err)
		}
	}

	for _, member := range removedMembers {
		err = doSafeUpdate(context.Background(), MembershipKey+"-"+member, true, func(gr *clientv3.GetResponse) (value string, err error) {

			if len(gr.Kvs) != 1 {
				return "", fmt.Errorf("removing user bad number of member keys: %d", len(gr.Kvs))
			}

			var memberCurrentGroups []string
			err = json.Unmarshal(gr.Kvs[0].Value, &memberCurrentGroups)
			if err != nil {
				return "", err
			}

			memberCurrentGroups = slices.DeleteFunc(memberCurrentGroups, func(s string) bool {
				return s == group
			})

			reverseMappingJson, _ := json.Marshal(memberCurrentGroups)

			return string(reverseMappingJson), nil
		})
		if err != nil {
			log.Println("failed to remove member ", member, "from group: ", err)
			errs = append(errs, err)
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("updating group information failed: %s", errs)
	}

	return nil
}

func GetGroups() (result []control.GroupData, err error) {

	resp, err := etcd.Get(context.Background(), GroupsPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, fmt.Errorf("failed to get group from etcd: %s", err)
	}

	for _, r := range resp.Kvs {

		var groupMembers []string
		err := json.Unmarshal(r.Value, &groupMembers)
		if err != nil {
			return nil, err
		}

		result = append(result, control.GroupData{
			Group:   string(bytes.TrimPrefix(r.Key, []byte(GroupsPrefix))),
			Members: groupMembers,
		})
	}

	return
}

func RemoveGroup(groupName string) error {

	if groupName == "*" {
		return fmt.Errorf("cannot delete default group")
	}

	delResp, err := etcd.Delete(context.Background(), GroupsPrefix+groupName, clientv3.WithPrevKV())
	if err != nil {
		return fmt.Errorf("failed to delete group: %s", err)
	}

	var oldMembers []string
	if len(delResp.PrevKvs) == 1 {
		err = json.Unmarshal(delResp.PrevKvs[0].Value, &oldMembers)
		if err != nil {
			return fmt.Errorf("failed to unmarshal old members: %s", err)
		}
	}

	var errs []error
	for _, member := range oldMembers {
		err = doSafeUpdate(context.Background(), MembershipKey+"-"+member, false, func(gr *clientv3.GetResponse) (value string, err error) {

			if len(gr.Kvs) != 1 {
				return "", errors.New("bad number of membership keys")
			}

			var memberCurrentGroups []string
			err = json.Unmarshal(gr.Kvs[0].Value, &memberCurrentGroups)
			if err != nil {
				return "", fmt.Errorf("failed to unmarshal current members: %s", err)
			}

			memberCurrentGroups = slices.DeleteFunc(memberCurrentGroups, func(s string) bool {
				return s == groupName
			})

			reverseMappingJson, _ := json.Marshal(memberCurrentGroups)

			return string(reverseMappingJson), nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("changing membership information failed: %s", errs)
	}

	return nil
}

func GetUserGroupMembership(username string) ([]string, error) {

	response, err := etcd.Get(context.Background(), MembershipKey+"-"+username)
	if err != nil {
		return nil, fmt.Errorf("failed to get membership information: %s", err)
	}

	if len(response.Kvs) == 0 {
		return []string{}, nil
	}

	var groupMembership []string

	err = json.Unmarshal(response.Kvs[0].Value, &groupMembership)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal group membership: %s", err)
	}

	groupMembership = append(groupMembership, "*")

	return groupMembership, nil
}

func SetUserGroupMembership(username string, newGroups []string) error {

	err := doSafeUpdate(context.Background(), MembershipKey+"-"+username, true, func(gr *clientv3.GetResponse) (value string, err error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("bad number of membership keys")
		}

		userGroups, _ := json.Marshal(newGroups)
		return string(userGroups), nil
	})

	return fmt.Errorf("failed to update group membership: %s", err)
}
