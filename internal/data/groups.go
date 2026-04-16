package data

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

// joined is a unix timestamp
func (d *database) generateOpsForGroupAddition(branch *tetcd.TxnConditional, joined int64, group string, usernames []string, sso bool) error {

	membership := config.MembershipInfo{
		Joined: joined,
		SSO:    sso,
	}

	for _, username := range usernames {
		err := tetcd.PutTx(branch, InternalConfig.Indexes.UserMembership().Key(username).Key(group), membership)
		if err != nil {
			return err
		}

		err = tetcd.PutTx(branch, Config.Acls.Groups().Key(group).Key(username), membership)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *database) CreateGroup(group string, initialMembers []string) error {

	if strings.Contains(group, "-") {
		return errors.New("group name cannot contain -")
	}

	index := InternalConfig.Indexes.Groups().Key(group)

	info := config.GroupInfo{
		Group:   group,
		Created: time.Now().Unix(),
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(clientv3util.KeyMissing(index.Key()))
	tetcd.PutTx(then, index, info)
	tetcd.PutTx(then, index, info)

	d.generateOpsForGroupAddition(then, info.Created, group, initialMembers, false)

	err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to complete transaction: %w", err)
	}

	if !txn.Succeeded() {
		return errors.New("group already exists")
	}

	return nil
}

func (d *database) GetGroups() (result []*control.GroupData, err error) {

	keys, err := InternalConfig.Indexes.Groups().Keys(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, fmt.Errorf("failed to get groups index from etcd: %w", err)
	}

	groups := map[string]*control.GroupData{}

	result = make([]*control.GroupData, 0, len(keys))

	txn := tetcd.NewTxn(context.Background(), d.etcd)

	memberHandles := make([]*tetcd.ListHandle[config.MembershipInfo], 0, len(keys))

	then := txn.Then()
	for _, groupName := range keys {

		group := &control.GroupData{
			Group: groupName,
		}
		groups[groupName] = group
		result = append(result, group)

		memberHandles = append(memberHandles, tetcd.ListTx(then, Config.Acls.Groups().Key(groupName)))
	}

	if err := txn.Commit(); err != nil {
		return nil, fmt.Errorf("failed to get group members")
	}

	// yet another O(MxN), pain
	for _, handle := range memberHandles {
		users, err := handle.Entries()
		if err != nil {
			log.Error().Err(err).Str("group", handle.Prefix()).Msg("failed to get users for group")
			continue
		}

		for username, membership := range users {

			if gd, ok := groups[filepath.Base(handle.Prefix())]; ok {

				gd.Members = append(gd.Members, control.MemberInfo{
					Name:   username,
					SSO:    membership.SSO,
					Joined: membership.Joined,
				})
			} else {
				log.Info().Str("group", filepath.Base(handle.Prefix())).Msg("group not found in map")
			}
		}

	}

	return result, nil
}

func (d *database) RemoveGroup(group string) error {

	if group == "*" {
		return fmt.Errorf("cannot delete default group")
	}

	index := InternalConfig.Indexes.Groups().Key(group)

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(clientv3util.KeyExists(index.Key()))

	tetcd.DeleteTx(then, index)
	membersH := tetcd.DeleteTx(then, Config.Acls.Groups().Key(group).All(), clientv3.WithPrefix(), clientv3.WithPrevKV())

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to remove group %q: %w", group, err)
	}

	if !txn.Succeeded() {
		return fmt.Errorf("group %q was deleted by another user", group)
	}

	txn = tetcd.NewTxn(context.Background(), d.etcd)
	then = txn.Then()

	members, err := membersH.PrevKeys()
	if err != nil {
		return fmt.Errorf("failed to get group membership indexes: %w", err)
	}

	for _, member := range members {
		tetcd.DeleteTx(then, InternalConfig.Indexes.UserMembership().Key(member).Key(group))
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to remove group membership indexes: %w", err)
	}

	return nil
}

func (d *database) GetUserGroupMembership(username string) ([]string, error) {

	groups, err := InternalConfig.Indexes.UserMembership().Key(username).Keys(context.Background(), d.etcd)
	if err != nil {
		return nil, fmt.Errorf("failed to get user group memberships: %w", err)
	}

	groupMembership := []string{"*"}

	for _, group := range groups {
		groupMembership = append(groupMembership, strings.TrimPrefix(group, "group:"))
	}

	return groupMembership, nil
}

func (d *database) RemoveUserAllGroups(username string) error {

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()
	groupsH := tetcd.DeleteTx(then, InternalConfig.Indexes.UserMembership().Key(username).All(), clientv3.WithPrefix(), clientv3.WithPrevKV())

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to remove user group memberships: %w", err)
	}

	groups, err := groupsH.PrevKeys()
	if err != nil {
		return fmt.Errorf("failed to get previous group keys: %w", err)
	}

	txn = tetcd.NewTxn(context.Background(), d.etcd)
	then = txn.Then()

	results := make([]*tetcd.DeleteHandle[config.MembershipInfo], 0, len(groups))
	for _, group := range groups {
		results = append(results, tetcd.DeleteTx(then, Config.Acls.Groups().Key(group).Key(username)))
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to remove user %q from groups: %w", username, err)
	}

	var errs []error
	for _, result := range results {
		_, err := result.Deleted()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %q: %w", result.Key(), err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}

	return nil
}

func (d *database) RemoveUserFromGroup(usernames []string, group string) error {
	if group == "*" {
		return fmt.Errorf("cannot remove user from default group")
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	responses := make([]*tetcd.DeleteHandle[config.MembershipInfo], 0, len(usernames))

	for _, username := range usernames {
		responses = append(responses, tetcd.DeleteTx(then, InternalConfig.Indexes.UserMembership().Key(username).Key(group)))
		responses = append(responses, tetcd.DeleteTx(then, Config.Acls.Groups().Key(group).Key(username)))
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to remove %d users from group %s: %w", len(usernames), group, err)
	}

	var errs []error
	for _, result := range responses {
		_, err := result.Deleted()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to remove %q: %w", result.Key(), err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}

	return nil
}

func (d *database) AddUserToGroups(usernames []string, groups []string, fromSSO bool) error {

	addition := time.Now().Unix()

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	subtxns := make([]*tetcd.SubTxn, 0, len(groups))
	// Ugh O(NxM)
	for _, group := range groups {

		subtxn := tetcd.SubTx(then)
		subtxns = append(subtxns, subtxn)

		then, _ := subtxn.Conditional(clientv3util.KeyExists(Config.Acls.Groups().Key(group).All().Key()))

		err := d.generateOpsForGroupAddition(then, addition, group, usernames, fromSSO)
		if err != nil {
			return fmt.Errorf("failed to generate ops for group addition: %w", err)
		}
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to add user %q to groups %s: %w", usernames, groups, err)
	}

	failures := 0
	for i := range subtxns {
		if !subtxns[i].Succeeded() {
			failures++
		}
	}

	if failures > 0 {
		return fmt.Errorf("failed to add %d groups", failures)
	}

	return nil
}

func (d *database) SetUserGroupMembership(username string, newGroups []string, fromSSO bool) error {

	err := d.RemoveUserAllGroups(username)
	if err != nil {
		return fmt.Errorf("failed to remove user groups to set them to specific list: %w", err)
	}

	return d.AddUserToGroups([]string{username}, newGroups, fromSSO)
}
