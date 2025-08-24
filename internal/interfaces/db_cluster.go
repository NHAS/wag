package interfaces

import (
	"time"

	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

type ClusterWriter interface {
	SetWitness(on bool) error
	ClusterNodeStepDown() error
	SetCurrentNodeVersion() error
	PromoteClusterMember(idHex string) error

	AddClusterMember(name, etcPeerUrlAddress, newManagerAddressURL string) (joinToken string, err error)
	RemoveClusterMember(idHex string) error

	SetDrained(idHex string, on bool) error
}

type ClusterReader interface {
	ClusterManagementEnabled() bool
	GetCurrentNodeID() types.ID
	IsCurrentNodeLearner() bool

	GetClusterNodeVersion(idHex string) (string, error)
	GetClusterNodeLastPing(idHex string) (time.Time, error)
	GetClusterLeader() types.ID
	GetClusterMembers() []*membership.Member

	ClusterHasLeader() bool

	IsClusterNodeDrained(idHex string) (bool, error)
	IsClusterNodeWitness(idHex string) (bool, error)
}

type ClusterMonitor interface {
	RegisterClusterHealthListener(f func(status string)) (string, error)
}

type Cluster interface {
	ClusterWriter
	ClusterReader
	ClusterMonitor
}
