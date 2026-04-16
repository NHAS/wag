package interfaces

import "github.com/NHAS/wag/internal/config"

type UserWriter interface {
	CreateUserDataAccount(username string) (config.UserModel, error)

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
	GetUserData(username string) (u config.UserModel, err error)
	GetUserDataFromAddress(address string) (u config.UserModel, err error)
	GetAllUsers() (users []config.UserModel, err error)
	GetUserGroupMembership(username string) ([]string, error)
}

type UserRepository interface {
	UserWriter
	UserReader
}
