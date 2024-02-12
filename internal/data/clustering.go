package data

import (
	"context"

	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

func GetServerID() string {
	return etcdServer.Server.ID().String()
}

func GetLeader() types.ID {
	return etcdServer.Server.Leader()
}

func HasLeader() bool {
	return etcdServer.Server.Leader() != 0
}

func IsLearner() bool {
	return etcdServer.Server.IsLearner()
}

func IsLeader() bool {
	return etcdServer.Server.Leader() == etcdServer.Server.ID()
}

func GetMembers() []*membership.Member {
	return etcdServer.Server.Cluster().Members()
}

func AddMember() error {
	mr, err := etcd.MemberAddAsLearner(context.Background(), []string{})
	if err != nil {
		return err
	}

}
