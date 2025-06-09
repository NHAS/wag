package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

type GroupInfo struct {
	Group   string
	Created int64
}

type MembershipInfo struct {
	Joined int64
}

func migrateGroups() {

}

// joined is a unix timestamp
func generateOpsForGroupAddition(joined int64, group string, usernames []string) []clientv3.Op {

	membership := MembershipInfo{
		Joined: joined,
	}

	membershipInfoBytes, _ := json.Marshal(membership)

	c := string(membershipInfoBytes)

	operations := []clientv3.Op{}
	for _, username := range usernames {

		operations = append(operations, clientv3.OpPut(fmt.Sprintf("%s%s-%s", GroupMembershipPrefix, username, group), c))
		operations = append(operations, clientv3.OpPut(fmt.Sprintf("%s%s-members-%s", GroupsPrefix, group, username), c))
	}

	return operations
}

func CreateGroup(group string, initialMembers []string) error {

	if strings.Contains(group, "-") {
		return errors.New("group name cannot contain -")
	}

	info := GroupInfo{
		Group:   group,
		Created: time.Now().Unix(),
	}

	groupInfoBytes, _ := json.Marshal(info)

	operations := []clientv3.Op{
		clientv3.OpPut(fmt.Sprintf("%s%s", GroupsIndexPrefix, group), ""),
		clientv3.OpPut(fmt.Sprintf("%s%s", GroupsPrefix, group), string(groupInfoBytes)),
	}

	operations = append(operations, generateOpsForGroupAddition(info.Created, group, initialMembers)...)

	txn := etcd.Txn(context.Background())
	txn.If(clientv3util.KeyMissing(GroupsPrefix + group))
	txn.Then(
		operations...,
	)

	resp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to complete transaction: %w", err)
	}

	if !resp.Succeeded {
		return errors.New("group already exists")
	}

	return nil
}

func GetGroups() (result []*control.GroupData, err error) {

	resp, err := etcd.Get(context.Background(), GroupsIndexPrefix, clientv3.WithPrefix(), clientv3.WithKeysOnly(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, fmt.Errorf("failed to get groups index from etcd: %s", err)
	}

	groups := map[string]*control.GroupData{}

	result = make([]*control.GroupData, 0, len(resp.Kvs))

	ops := []clientv3.Op{}
	for _, r := range resp.Kvs {
		groupName := strings.TrimPrefix(string(r.Key), GroupsIndexPrefix)

		group := &control.GroupData{
			Group: groupName,
		}
		groups[groupName] = group
		result = append(result, group)

		ops = append(ops, clientv3.OpGet(fmt.Sprintf("%s%s-members-", GroupsPrefix, groupName), clientv3.WithPrefix(), clientv3.WithKeysOnly()))
	}

	txn := etcd.Txn(context.Background())
	txn.Then(ops...)
	response, err := txn.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to get group members")
	}

	// yet another O(N^2), pain
	for _, resp := range response.Responses {
		kvs := resp.GetResponseRange().Kvs
		for _, kv := range kvs {
			resultParts, err := SplitKey(3, GroupsPrefix, string(kv.Key))
			if err != nil {
				log.Println("failed to get group: ", err)
				continue
			}
			// 1 = -members-

			// 0 = groupName
			// 2 = username
			if gd, ok := groups[resultParts[0]]; ok {
				gd.Members = append(gd.Members, resultParts[2])
			}
		}

	}

	return result, nil
}

func RemoveGroup(group string) error {

	if group == "*" {
		return fmt.Errorf("cannot delete default group")
	}

	// Get main group info key
	groupKey := fmt.Sprintf("%s%s", GroupsPrefix, group)
	groupResp, err := etcd.Get(context.Background(), groupKey)
	if err != nil {
		return fmt.Errorf("failed to remove group %q, getting group metadata failed: %w", group, err)
	}

	if groupResp.Count == 0 {
		return fmt.Errorf("could not find group %q", group)
	}

	// Get all members
	membersKey := fmt.Sprintf("%s%s-members-", GroupsPrefix, group)
	membersResp, err := etcd.Get(
		context.Background(),
		membersKey,
		clientv3.WithPrefix(),
		clientv3.WithKeysOnly(),
	)
	if err != nil {
		return fmt.Errorf("failed to get group members of %q: %w", group, err)
	}

	// Delete the group, then delete all the members

	ops := []clientv3.Op{
		clientv3.OpDelete(fmt.Sprintf("%s%s", GroupsIndexPrefix, group)),
		clientv3.OpDelete(groupKey),
		clientv3.OpDelete(membersKey, clientv3.WithPrefix()),
	}

	for _, member := range membersResp.Kvs {
		user := strings.TrimPrefix(string(member.Key), membersKey)
		ops = append(ops, clientv3.OpDelete(fmt.Sprintf("%s%s-%s", GroupMembershipPrefix, user, group)))
	}

	txn := etcd.Txn(context.Background())
	txn.If(clientv3util.KeyExists(groupKey)) // Ensure group still exists
	txn.Then(
		ops...,
	)

	resp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to remove group %q: %w", group, err)
	}

	if !resp.Succeeded {
		return fmt.Errorf("group %q was deleted by another user", group)
	}

	return nil
}

func GetUserGroupMembership(username string) ([]string, error) {

	membershipsKey := fmt.Sprintf("%s%s-", GroupMembershipPrefix, username)
	response, err := etcd.Get(context.Background(), membershipsKey, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, fmt.Errorf("failed to get membership information: %s", err)
	}

	if len(response.Kvs) == 0 {
		return []string{"*"}, nil
	}

	groupMembership := []string{"*"}

	for _, group := range response.Kvs {
		groupMembership = append(groupMembership, strings.TrimPrefix(strings.TrimPrefix(string(group.Key), membershipsKey), "group:"))
	}

	return groupMembership, nil
}

func RemoveUserAllGroups(username string) error {

	membershipsKey := fmt.Sprintf("%s%s-", GroupMembershipPrefix, username)
	response, err := etcd.Delete(context.Background(), membershipsKey, clientv3.WithPrefix(), clientv3.WithPrevKV(), clientv3.WithKeysOnly())
	if err != nil {
		return fmt.Errorf("failed to get membership information: %s", err)
	}

	if len(response.PrevKvs) == 0 {
		return nil
	}

	ops := make([]clientv3.Op, 0, len(response.PrevKvs))
	for _, groupKvs := range response.PrevKvs {
		group := strings.TrimPrefix(string(groupKvs.Key), membershipsKey)
		// delete all references within the group itself
		ops = append(ops, clientv3.OpDelete(fmt.Sprintf("%s%s-members-%s", GroupsPrefix, group, username)))
	}

	// delete all subkeys for the user membership information
	ops = append(ops, clientv3.OpDelete(membershipsKey, clientv3.WithPrefix()))

	txn := etcd.Txn(context.Background())
	txn.Then(ops...)

	_, err = txn.Commit()
	return err
}

func RemoveUserFromGroup(usernames []string, group string) error {
	if group == "*" {
		return fmt.Errorf("cannot remove user from default group")
	}

	ops := []clientv3.Op{}
	for _, username := range usernames {
		ops = append(ops, clientv3.OpDelete(fmt.Sprintf("%s%s-%s", GroupMembershipPrefix, username, group)))
		ops = append(ops, clientv3.OpDelete(fmt.Sprintf("%s%s-members-%s", GroupsPrefix, group, username)))
	}

	txn := etcd.Txn(context.Background())
	txn.Then(
		ops...,
	)

	_, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to remove %d users from group %s: %w", len(usernames), group, err)
	}

	return nil
}

func AddUserToGroups(usernames []string, groups []string) error {

	addition := time.Now().Unix()

	ops := []clientv3.Op{}
	// Ugh O(N^2)
	for _, group := range groups {
		ops = append(ops, generateOpsForGroupAddition(addition, group, usernames)...)
	}

	txn := etcd.Txn(context.Background())
	txn.Then(ops...)

	_, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to add user %q to groups %s: %w", usernames, groups, err)
	}

	return nil
}

func SetUserGroupMembership(username string, newGroups []string) error {

	err := RemoveUserAllGroups(username)
	if err != nil {
		return fmt.Errorf("failed to remove user groups to set them to specific list: %w", err)
	}

	return AddUserToGroups([]string{username}, newGroups)
}
