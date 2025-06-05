package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"go.etcd.io/etcd/client/pkg/v3/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
)

func GetServerID() types.ID {
	return etcdServer.Server.ID()
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

// StepDown when called on a leader node, to transfer ownership to another node (demoted)
func StepDown() error {
	return etcdServer.Server.TransferLeadership()
}

func GetMembers() []*membership.Member {

	return etcdServer.Server.Cluster().Members()
}

func GetLastPing(idHex string) (time.Time, error) {
	id, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return time.Time{}, err
	}

	if etcdServer.Server.Cluster().Member(types.ID(id)) == nil {
		return time.Time{}, errors.New("id is not part of cluster")
	}

	lastPing, err := etcd.Get(context.Background(), path.Join(NodeInfo, idHex, "ping"))
	if err != nil {
		return time.Time{}, err
	}

	if lastPing.Count == 0 {
		return time.Time{}, errors.New("node missing")
	}

	if len(lastPing.Kvs) != 1 {
		return time.Time{}, errors.New("multiple keys match ping")
	}

	t, err := time.Parse(time.RFC1123Z, string(lastPing.Kvs[0].Value))
	if err != nil {
		return t, err
	}

	return t, nil
}

func SetWitness(on bool) error {
	if on {
		_, err := etcd.Put(context.Background(), path.Join(NodeInfo, GetServerID().String(), "witness"), fmt.Sprintf("%t", on))
		return err
	}

	_, err := etcd.Delete(context.Background(), path.Join(NodeInfo, GetServerID().String(), "witness"))
	return err
}

func IsWitness(idHex string) (bool, error) {
	_, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return false, fmt.Errorf("bad member ID arg (%v), expecting ID in Hex", err)
	}

	isDrained, err := etcd.Get(context.Background(), path.Join(NodeInfo, idHex, "witness"))
	if err != nil {
		return false, err
	}

	return isDrained.Count != 0, nil
}

func GetVersion(idHex string) (string, error) {
	_, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("bad member ID arg (%v), expecting ID in Hex", err)
	}
	return get[string](path.Join(NodeInfo, idHex, "version"))
}

func SetVersion() error {
	d, _ := json.Marshal(config.Version)
	_, err := etcd.Put(context.Background(), path.Join(NodeInfo, GetServerID().String(), "version"), string(d))
	return err
}

func SetDrained(idHex string, on bool) error {

	isWitness, err := IsWitness(idHex)
	if err != nil {
		return err
	}

	if isWitness {
		return errors.New("cannot set drained on witness node, this node is not serving clients")
	}

	_, err = strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return err
	}

	if on {
		_, err = etcd.Put(context.Background(), path.Join(NodeInfo, idHex, "drain"), fmt.Sprintf("%t", on))
		return err
	}

	_, err = etcd.Delete(context.Background(), path.Join(NodeInfo, idHex, "drain"))
	return err
}

func IsDrained(idHex string) (bool, error) {
	_, err := strconv.ParseUint(idHex, 16, 64)
	if err != nil {
		return false, fmt.Errorf("bad member ID arg (%v), expecting ID in Hex", err)
	}

	isDrained, err := etcd.Get(context.Background(), path.Join(NodeInfo, idHex, "drain"))
	if err != nil {
		return false, err
	}

	return isDrained.Count != 0, nil
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

	// If no name is supplied, use the hostname
	if name == "" {
		name = newUrl.Hostname()
	}

	if newManagerAddressURL == "" {
		newManagerAddressURL = "https://" + newUrl.Hostname() + ":4545"
	}

	if net.ParseIP(newUrl.Hostname()) == nil {

		addresses, err := net.LookupIP(newUrl.Hostname())
		if err != nil {
			return "", fmt.Errorf("unable to lookup new etcd listen address hostname: %s", err)
		}

		if len(addresses) == 0 {
			return "", fmt.Errorf("no addresses found for hostname: %s", newUrl.Hostname())
		}

		newUrl.Host = addresses[0].String()
	}

	if newUrl.Port() == "" {
		newUrl.Host = newUrl.Host + ":2380"
	}

	// From this point forward the newURL will contain the IP address of the etcd cluster member

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

	copyValues.Webserver.Management.Enabled = false
	copyValues.Webserver.Management.ListenAddress = ""

	b, _ := json.Marshal(copyValues)
	token.SetAdditional("config.json", string(b))

	_, err = etcd.MemberAddAsLearner(context.Background(), []string{newUrl.String()})
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

	// Clear any node metadata
	_, err = etcd.Delete(context.Background(), path.Join(NodeInfo, idHex), clientv3.WithPrefix())
	if err != nil {
		return err
	}

	_, err = etcd.MemberRemove(context.Background(), id)
	if err != nil {
		return err
	}

	return nil
}
