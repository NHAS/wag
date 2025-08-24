package integration

import (
	"slices"
	"testing"

	"github.com/NHAS/wag/pkg/control"
)

func TestGroups(t *testing.T) {
	groups, err := ctrl.GetGroups()
	if err != nil {
		t.Fatal("should be able to get groups, ", err)
	}

	if len(groups) == 0 {
		t.Fatal("group should not be 0 to start with")
	}

	const (
		groupName   = "group:snazz"
		initialUser = "unique_name"
	)

	err = ctrl.AddGroup(control.GroupCreateData{
		Group: groupName,
		AddedMembers: []string{
			initialUser,
		},
	})

	if err != nil {
		t.Fatal("should be able to add a unique group: ", err)
	}

	groups, err = ctrl.GetGroups()
	if err != nil {
		t.Fatal("should be able to refetch group after add: ", err)
	}

	if !slices.ContainsFunc(groups, func(group control.GroupData) bool {
		return group.Group == groupName &&
			len(group.Members) == 1 &&
			slices.ContainsFunc(group.Members, func(member control.MemberInfo) bool {
				return member.SSO == false && member.Name == initialUser
			})
	}) {
		t.Fatal("groups did not contain newly created group: ", groups)
	}

	const (
		addedUser = "albert"
	)

	err = ctrl.EditGroup(control.GroupEditData{
		GroupCreateData: control.GroupCreateData{
			Group: groupName,
			AddedMembers: []string{
				addedUser,
			},
		},
		RemovedMembers: []string{
			initialUser,
		},
	})

	if err != nil {
		t.Fatal("should be able to add and remove from group: ", err)
	}

	groups, err = ctrl.GetGroups()
	if err != nil {
		t.Fatal("should be able to refetch group after edit: ", err)
	}

	if !slices.ContainsFunc(groups, func(group control.GroupData) bool {
		return group.Group == groupName &&
			len(group.Members) == 1 &&
			slices.ContainsFunc(group.Members, func(member control.MemberInfo) bool {
				return member.SSO == false && member.Name == addedUser
			})
	}) {
		t.Fatal("groups did not contain modified group: ", groups)
	}

	err = ctrl.RemoveGroup([]string{groupName})
	if err != nil {
		t.Fatal("should be able to delete group: ", err)
	}

	groups, err = ctrl.GetGroups()
	if err != nil {
		t.Fatal("should be able to refetch group after delete: ", err)
	}

	if slices.ContainsFunc(groups, func(group control.GroupData) bool {
		return group.Group == groupName
	}) {
		t.Fatal("groups should not contain group after deletion")
	}

}

func TestGroupMembership(t *testing.T) {
	const (
		groupName   = "group:toaster2"
		initialUser = "unique_name_2"
	)

	err := ctrl.AddGroup(control.GroupCreateData{
		Group: groupName,
		AddedMembers: []string{
			initialUser,
		},
	})

	if err != nil {
		t.Fatal("should be able to add a unique group: ", err)
	}

	groups, err := ctrl.UserGroups(initialUser)
	if err != nil {
		t.Fatal("should be able to query user groups: ", err)
	}

	// this is 2 because every user is part of the all group: *
	if len(groups) != 2 {
		t.Fatal("user had an incorrect number of groups associated: ", groups)
	}

	err = ctrl.EditGroup(control.GroupEditData{
		GroupCreateData: control.GroupCreateData{
			Group: groupName,
		},
		RemovedMembers: []string{initialUser},
	})
	if err != nil {
		t.Fatal("should be able to edit group: ", err)
	}

	groups, err = ctrl.UserGroups(initialUser)
	if err != nil {
		t.Fatal("should be able to query user groups after edit: ", err)
	}

	// this is one because every user is part of the all group
	if len(groups) != 1 {
		t.Fatal("user had an incorrect number of groups associated: ", groups)
	}

}
