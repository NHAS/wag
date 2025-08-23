package interfaces

import (
	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type SessionsRepository interface {
	GetAllSessions() (sessions []data.DeviceSession, err error)
}

type RawRV interface {
	Put(key, value string) error
	Get(key string) ([]byte, error)
}

type GroupsRepository interface {
	CreateGroup(group string, initialMembers []string) error
	GetGroups() (result []*control.GroupData, err error)
	RemoveGroup(group string) error
}

type AclsRepository interface {
	RemoveAcl(effects string) error
	SetAcl(effects string, policy acls.Acl, overwrite bool) error
	GetPolicies() (result []control.PolicyData, err error)
}

type Errors interface {
	GetAllErrors() (ret []data.EventError, err error)
	RaiseError(raisedError error, value []byte)
	ResolveError(errorId string) error
}

type BootstrapRepositoryReader interface {
	GetInitialData() (users []data.UserModel, devices []data.Device, err error)
}

type EventQueueReader interface {
	GetEventQueue() []data.GeneralEvent
}

type RawConnection interface {
	Raw() *clientv3.Client
}

type EventWriter interface {
	Write(e data.GeneralEvent) error
}

type Webhooks interface {
	CreateTempWebhook() (string, error)
	WebhookRecordLastRequest(id string, request string) error

	CreateWebhook(webhook data.WebhookCreateRequestDTO) error
	GetWebhook(id string) (data.WebhookGetResponseDTO, error)
	GetWebhooks() (hooks []data.WebhookGetResponseDTO, err error)
	DeleteWebhooks(ids []string) error

	GetLastWebhookRequestPath(id string, additionals ...string) string
	GetWebhookLastRequest(id string) (string, error)
	WebhookExists(id string) bool
}

type Watchers interface {
	RawConnection
	EventWriter
	Errors
}

type Database interface {
	BootstrapRepositoryReader
	EventQueueReader

	ConfigRepository

	GroupsRepository
	AuthenticationActions
	UserRepository
	AclsRepository
	MFARespository
	RegistrationRepository
	DeviceRepository
	Webhooks

	SessionsRepository

	AdminRepository
	Errors
	Cluster

	Watchers

	// todo remove from here
	SplitKey(expected int, stripPrefix, key string) ([]string, error)

	RawRV

	RawConnection

	Teardown
}
