package interfaces

import "github.com/NHAS/wag/internal/data"

type AdminWriter interface {
	CreateLocalAdminUser(username, password string, changeOnFirstUse bool) error
	CreateOidcAdminUser(username, guid string) (data.AdminUserDTO, error)

	DeleteAdminUser(username string) error

	SetAdminUserLock(username string) error
	SetAdminUserUnlock(username string) error
	SetAdminPassword(username, password string) error
}

type AdminReader interface {
	GetAdminUser(id string) (a data.AdminUserDTO, err error)
	GetAllAdminUsers() (adminUsers []data.AdminUserDTO, err error)

	CompareAdminKeys(username, password string) error
}

type AdminRepository interface {
	AdminWriter
	AdminReader
}
