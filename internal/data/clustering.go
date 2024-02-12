package data

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/NHAS/wag/internal/config"
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

func AddMember(name, urlAddress string) (ret config.ClusteringDetails, err error) {

	newUrl, err := url.Parse(urlAddress)
	if err != nil {
		return ret, err
	}

	if !strings.Contains(newUrl.Host, ":") {
		return ret, errors.New("url must contain port")
	}

	resp, err := etcd.MemberAddAsLearner(context.Background(), []string{urlAddress})
	if err != nil {
		return ret, err
	}

	newID := resp.Member.ID

	ret.Name = name

	ret.ListenAddresses = []string{newUrl.Host}

	// Effectively making our version of this
	// https://github.com/etcd-io/etcd/blob/42f0cb9762cafa440a3f77884b0deb454ccb22c5/etcdctl/ctlv3/command/member_command.go#L125

	for _, memb := range resp.Members {
		n := memb.Name
		if memb.ID == newID {
			n = name
		}
		ret.Peers[n] = memb.PeerURLs
	}

	return ret, nil
}

func PromoteMember(idHex string) error {
	id, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return fmt.Errorf("bad member ID arg (%v), expecting ID in Hex", err)
	}

	_, err = etcd.MemberPromote(context.Background(), id)
	if err != nil {
		return err
	}

	return nil
}
