package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/NHAS/wag/internal/config"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

type NewNodeRequest struct {
	NodeName      string
	ConnectionURL string
	ManagerURL    string
}

type NewNodeResponse struct {
	JoinToken string
}

type NodeControlRequest struct {
	Node   string
	Action string
}

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

// AddMember adds a new node to the etcd cluster, and subsequently wag.
// This is done by creating a join token which allows an existing member to issue the CA private key, and download the wag config
// etcPeerUrlAddress is where the new node etcd instance is contactable
// newManagerAddressURL is where the tls manager will listen (i.e the place that serves tls certs and config)
func AddMember(name, etcPeerUrlAddress, newManagerAddressURL string) (joinToken string, err error) {

	if !strings.HasPrefix(etcPeerUrlAddress, "https://") {
		return "", errors.New("url must be https://")
	}

	newUrl, err := url.Parse(etcPeerUrlAddress)
	if err != nil {
		return "", err
	}

	if newUrl.Port() == "" {
		newUrl.Host = newUrl.Host + ":443"
	}

	// Determine the listen ip address
	listenAddr := newUrl.Hostname()

	if net.ParseIP(newUrl.Hostname()) == nil {

		addresses, err := net.LookupIP(newUrl.Hostname())
		if err != nil {
			return "", fmt.Errorf("unable to lookup new etcd listen address hostname: %s", err)
		}

		if len(addresses) == 0 {
			return "", fmt.Errorf("no addresses found for hostname: %s", newUrl.Hostname())
		}

		listenAddr = addresses[0].String()
	}

	if newUrl.Port() != "" {
		listenAddr += ":" + newUrl.Port()
	} else {
		listenAddr += ":443"
	}
	newUrl.Host = listenAddr

	if newManagerAddressURL == "" {
		newManagerAddressURL = "https://" + newUrl.Hostname() + ":4545"
	}

	token, err := TLSManager.CreateToken(newManagerAddressURL)
	if err != nil {
		return "", err
	}

	copyValues := config.Values

	response, err := etcd.MemberList(context.Background())
	if err != nil {
		return "", err
	}

	for _, m := range response.Members {
		if m.IsLearner {
			continue
		}
		copyValues.Clustering.Peers[m.Name] = m.GetPeerURLs()
	}

	delete(copyValues.Clustering.Peers, name)

	copyValues.Clustering.ClusterState = "existing"
	copyValues.Clustering.Name = name
	copyValues.Clustering.ListenAddresses = []string{newUrl.String()}
	copyValues.Clustering.TLSManagerListenURL = newManagerAddressURL

	copyValues.Acls = config.Acls{}
	copyValues.Acls.Groups = map[string][]string{}

	b, _ := json.Marshal(copyValues)
	token.SetAdditional("config.json", string(b))

	_, err = etcd.MemberAddAsLearner(context.Background(), []string{etcPeerUrlAddress})
	if err != nil {
		return "", err
	}

	return token.Token, nil
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

func RemoveMember(idHex string) error {
	id, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return fmt.Errorf("bad member ID arg (%v), expecting ID in Hex", err)
	}

	_, err = etcd.MemberRemove(context.Background(), id)
	if err != nil {
		return err
	}

	return nil
}
