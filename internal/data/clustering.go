package data

import "go.etcd.io/etcd/server/v3/etcdserver/api/membership"

func GetServerID() string {
	return etcdServer.Server.ID().String()
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
