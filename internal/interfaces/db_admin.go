package interfaces

import (
	"github.com/NHAS/wag/internal/config"
)

type AdminWriter interface {
	CreateLocalAdminUser(username, password string, changeOnFirstUse bool) error
	CreateOidcAdminUser(username, guid string) (config.AdminUserDTO, error)

	DeleteAdminUser(username string) error

	SetAdminUserLock(username string) error
	SetAdminUserUnlock(username string) error
	SetAdminPassword(username, password string) error
}

type AdminReader interface {
	GetAdminUser(id string) (a config.AdminUserDTO, err error)
	GetOidcAdminUser(subject string) (a config.AdminUserDTO, err error)
	GetAllAdminUsers() (adminUsers []config.AdminUserDTO, err error)

	CompareAdminKeys(username, password string) error
}

type AdminRepository interface {
	AdminWriter
	AdminReader
}
