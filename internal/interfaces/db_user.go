package interfaces

import "github.com/NHAS/wag/internal/data"

type UserWriter interface {
	SetUserMfa(username, value, mfaType string) error

	SetUserLock(username string) error
	SetUserUnlock(username string) error

	AddUserToGroups(usernames []string, groups []string, fromSSO bool) error
	RemoveUserFromGroup(usernames []string, group string) error
	RemoveUserAllGroups(username string) error

	SetUserGroupMembership(username string, newGroups []string, fromSSO bool) error

	DeleteUser(username string) error
}

type UserReader interface {
	GetAllUsers() (users []data.UserModel, err error)
	GetUserGroupMembership(username string) ([]string, error)
}

type UserRepository interface {
	UserWriter
	UserReader
}
