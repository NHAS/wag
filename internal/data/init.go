package data

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NHAS/autoetcdtls/manager"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	_ "github.com/mattn/go-sqlite3"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
	"go.etcd.io/etcd/server/v3/embed"
)

var (
	etcd                   *clientv3.Client
	etcdServer             *embed.Etcd
	allowedTokenCharacters = regexp.MustCompile(`[a-zA-Z0-9\-\_\.]+`)
	TLSManager             *manager.Manager
)

func parseUrls(values ...string) []url.URL {
	urls := make([]url.URL, 0, len(values))
	for _, s := range values {
		u, err := url.Parse(s)
		if err != nil {
			log.Printf("Invalid url %s: %s", s, err.Error())
			continue
		}
		urls = append(urls, *u)
	}
	return urls
}

func Load(path, joinToken string, testing bool) error {

	var err error

	if TLSManager == nil {
		if joinToken == "" {
			TLSManager, err = manager.New(config.Values.Clustering.TLSManagerStorage, config.Values.Clustering.TLSManagerListenURL)
			if err != nil {
				return fmt.Errorf("tls manager: %w", err)
			}
		} else {

			if config.Values.Clustering.TLSManagerStorage == "" {
				config.Values.Clustering.TLSManagerStorage = "certificates"
			}

			TLSManager, err = manager.Join(joinToken, config.Values.Clustering.TLSManagerStorage, map[string]func(name string, data string){
				"config.json": func(name, data string) {
					err := os.WriteFile("config.json", []byte(data), 0600)
					if err != nil {
						log.Fatal("failed to create config.json from other cluster members config: ", err)
					}

					log.Println("got additional, loading config file")
					err = config.Load("config.json")
					if err != nil {
						log.Fatal("config supplied by other cluster member was invalid (potential version issues?): ", err)
					}
				},
			})
			if err != nil {
				return err
			}
		}
	}
	part, err := utils.GenerateRandomHex(10)
	if err != nil {
		return err
	}
	etcdUnixSocket := "unix:///tmp/wag.etcd." + part

	cfg := embed.NewConfig()
	cfg.Name = config.Values.Clustering.Name
	if testing {
		cfg.Name += part
	}
	cfg.ClusterState = config.Values.Clustering.ClusterState
	cfg.InitialClusterToken = "wag"
	cfg.LogLevel = config.Values.Clustering.ETCDLogLevel
	cfg.ListenPeerUrls = parseUrls(config.Values.Clustering.ListenAddresses...)
	cfg.ListenClientUrls = parseUrls(etcdUnixSocket)
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls
	cfg.AutoCompactionMode = "periodic"
	cfg.AutoCompactionRetention = "1h"
	cfg.SnapshotCount = 50000

	cfg.PeerTLSInfo.ClientCertAuth = true
	cfg.PeerTLSInfo.TrustedCAFile = TLSManager.GetCACertPath()
	cfg.PeerTLSInfo.CertFile = TLSManager.GetPeerCertPath()
	cfg.PeerTLSInfo.KeyFile = TLSManager.GetPeerKeyPath()

	if _, ok := config.Values.Clustering.Peers[cfg.Name]; ok {
		return fmt.Errorf("clustering.peers contains the same name (%s) as this node this would trample something and break", cfg.Name)
	}

	peers := config.Values.Clustering.Peers
	peers[cfg.Name] = config.Values.Clustering.ListenAddresses

	cfg.InitialCluster = ""
	for tag, addresses := range peers {
		cfg.InitialCluster += fmt.Sprintf("%s=%s", tag, strings.Join(addresses, ",")) + ","
	}

	cfg.InitialCluster = cfg.InitialCluster[:len(cfg.InitialCluster)-1]

	cfg.Dir = filepath.Join(config.Values.Clustering.DatabaseLocation, cfg.Name+".wag-node.etcd")
	etcdServer, err = embed.StartEtcd(cfg)
	if err != nil {
		return fmt.Errorf("error starting etcd: %s", err)
	}

	select {
	case <-etcdServer.Server.ReadyNotify():
		break
	case <-time.After(60 * time.Second):
		etcdServer.Server.Stop() // trigger a shutdown
		return errors.New("etcd took too long to start")
	}

	etcd, err = clientv3.New(clientv3.Config{
		Endpoints: []string{etcdUnixSocket},
	})
	if err != nil {
		return err
	}

	log.Println("Successfully connected to etcd")

	if !etcdServer.Server.IsLearner() {
		// After first run this will be a no-op
		err = loadInitialSettings()
		if err != nil {
			return err
		}

	}

	go checkClusterHealth()

	return nil
}

func loadInitialSettings() error {
	response, err := etcd.Get(context.Background(), "wag-acls-", clientv3.WithPrefix())
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no acls found in database, importing from .json file (from this point the json file will be ignored)")

		for aclName, acl := range config.Values.Acls.Policies {
			aclJson, _ := json.Marshal(acl)
			_, err = etcd.Put(context.Background(), "wag-acls-"+aclName, string(aclJson))
			if err != nil {
				return err
			}
		}
	}

	response, err = etcd.Get(context.Background(), GroupsPrefix, clientv3.WithPrefix())
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no groups found in database, importing from .json file (from this point the json file will be ignored)")

		for groupName, members := range config.Values.Acls.Groups {
			if err := SetGroup(groupName, members, true); err != nil {
				return err
			}
		}

	}

	configData, _ := json.Marshal(config.Values)
	err = putIfNotFound(fullJsonConfigKey, string(configData), "full config")
	if err != nil {
		return err
	}

	err = putIfNotFound(helpMailKey, config.Values.Webserver.Tunnel.HelpMail, "help mail")
	if err != nil {
		return err
	}

	err = putIfNotFound(externalAddressKey, config.Values.Webserver.Public.ExternalAddress, "external wag address")
	if err != nil {
		return err
	}

	err = putIfNotFound(dnsKey, config.Values.Wireguard.DNS, "dns")
	if err != nil {
		return err
	}

	err = putIfNotFound(InactivityTimeoutKey, config.Values.Webserver.Tunnel.SessionInactivityTimeoutMinutes, "inactivity timeout")
	if err != nil {
		return err
	}

	err = putIfNotFound(SessionLifetimeKey, config.Values.Webserver.Tunnel.MaxSessionLifetimeMinutes, "max session life")
	if err != nil {
		return err
	}

	err = putIfNotFound(LockoutKey, config.Values.Webserver.Lockout, "lockout")
	if err != nil {
		return err
	}

	err = putIfNotFound(IssuerKey, config.Values.Webserver.Tunnel.Issuer, "issuer name")
	if err != nil {
		return err
	}

	err = putIfNotFound(defaultWGFileNameKey, config.Values.Webserver.Public.DownloadConfigFileName, "wireguard config file")
	if err != nil {
		return err
	}

	err = putIfNotFound(checkUpdatesKey, config.Values.CheckUpdates, "update check settings")
	if err != nil {
		return err
	}

	err = putIfNotFound(MFAMethodsEnabledKey, config.Values.Webserver.Tunnel.Methods, "authorisation methods")
	if err != nil {
		return err
	}

	err = putIfNotFound(DefaultMFAMethodKey, config.Values.Webserver.Tunnel.DefaultMethod, "default mfa method")
	if err != nil {
		return err
	}

	err = putIfNotFound(OidcDetailsKey, config.Values.Webserver.Tunnel.OIDC, "oidc settings")
	if err != nil {
		return err
	}

	err = putIfNotFound(PamDetailsKey, config.Values.Webserver.Tunnel.PAM, "pam settings")
	if err != nil {
		return err
	}

	err = putIfNotFound(AcmeEmailKey, config.Values.Webserver.Acme.Email, "acme email")
	if err != nil {
		return err
	}

	err = putIfNotFound(AcmeProviderKey, config.Values.Webserver.Acme.CAProvider, "acme provider")
	if err != nil {
		return err
	}

	var token CloudflareToken
	token.APIToken = config.Values.Webserver.Acme.CloudflareDNSToken
	err = putIfNotFound(AcmeDNS01CloudflareAPIToken, token, "acme cloudflare dns api token")
	if err != nil {
		return err
	}

	tunnelWebserverConfig := WebserverConfiguration{
		ListenAddress: net.JoinHostPort(config.Values.Wireguard.ServerAddress.String(), config.Values.Webserver.Tunnel.Port),
		Domain:        config.Values.Webserver.Tunnel.Domain,
		TLS:           config.Values.Webserver.Tunnel.TLS,
	}

	if config.Values.Webserver.Tunnel.CertificatePath != "" {
		tunnelWebserverConfig.CertificatePEM, tunnelWebserverConfig.PrivateKeyPEM, err = readTLSPems(config.Values.Webserver.Tunnel.CertificatePath, config.Values.Webserver.Tunnel.PrivateKeyPath)
		if err != nil {
			log.Printf("WARNING, failed to read tunnel TLS material: %s", err)
		}
	}

	err = putIfNotFound(TunnelWebServerConfigKey, tunnelWebserverConfig, "tunnel web server config")
	if err != nil {
		return err
	}

	publicWebserverConfig := WebserverConfiguration{
		Domain:        config.Values.Webserver.Public.Domain,
		TLS:           config.Values.Webserver.Public.TLS,
		ListenAddress: config.Values.Webserver.Public.ListenAddress,
	}

	if config.Values.Webserver.Public.CertificatePath != "" {
		publicWebserverConfig.CertificatePEM, publicWebserverConfig.PrivateKeyPEM, err = readTLSPems(config.Values.Webserver.Public.CertificatePath, config.Values.Webserver.Public.PrivateKeyPath)
		if err != nil {
			log.Printf("WARNING, failed to read public webserver TLS material: %s", err)
		}
	}

	err = putIfNotFound(PublicWebServerConfigKey, publicWebserverConfig, "public/enrolment web server config")
	if err != nil {
		return err
	}

	managementWebserverConfig := WebserverConfiguration{
		Domain:        config.Values.Webserver.Management.Domain,
		TLS:           config.Values.Webserver.Management.TLS,
		ListenAddress: config.Values.Webserver.Management.ListenAddress,
	}

	if config.Values.Webserver.Management.CertificatePath != "" {

		managementWebserverConfig.CertificatePEM, managementWebserverConfig.PrivateKeyPEM, err = readTLSPems(config.Values.Webserver.Management.CertificatePath, config.Values.Webserver.Management.PrivateKeyPath)
		if err != nil {
			log.Printf("WARNING, failed to read public webserver TLS material: %s", err)
		}
	}

	err = putIfNotFound(ManagementWebServerConfigKey, managementWebserverConfig, "management web server config")
	if err != nil {
		return err
	}

	return nil
}

func readTLSPems(cert, key string) (string, string, error) {

	certBytes, err := os.ReadFile(cert)
	if err != nil {
		return "", "", fmt.Errorf("unable to read certificate file at path %q, %w", cert, err)
	}

	p, _ := pem.Decode(certBytes)
	if p == nil {
		return "", "", fmt.Errorf("failed to to decode certificate %q bytes", cert)
	}

	keyBytes, err := os.ReadFile(key)
	if err != nil {
		return "", "", fmt.Errorf("unable to read certificate file at path %q, %w", key, err)
	}

	p, _ = pem.Decode(keyBytes)
	if p == nil {
		return "", "", fmt.Errorf("failed to to decode key %q bytes", cert)
	}

	return string(certBytes), string(keyBytes), nil
}

func putIfNotFound[T any](key string, value T, set string) error {

	d, err := json.Marshal(value)
	if err != nil {
		return err
	}

	txn := etcd.Txn(context.Background())
	resp, err := txn.If(clientv3util.KeyMissing(key)).Then(clientv3.OpPut(key, string(d))).Commit()
	if err != nil {
		return err
	}

	if resp.Succeeded {
		log.Printf("setting %s from json, importing from .json file (from this point the json file will be ignored)", set)
	}

	return nil
}

func TearDown() {
	close(exit)
	if etcdServer != nil {

		etcd.Close()
		etcdServer.Close()

		etcd = nil
		etcdServer = nil
	}
}

func doSafeUpdate(ctx context.Context, key string, create bool, mutateFunc func(*clientv3.GetResponse) (value string, err error)) error {
	//https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L382
	var opts []clientv3.OpOption

	if mutateFunc == nil {
		return errors.New("no mutate function set in safe update")
	}

	origState, err := etcd.Get(ctx, key, opts...)
	if err != nil {
		return err
	}

	if create && origState.Count == 0 {

		newValue, err := mutateFunc(origState)
		if err != nil {
			return err
		}

		txnResp, err := etcd.KV.Txn(ctx).If(
			clientv3util.KeyMissing(key),
		).Then(
			clientv3.OpPut(key, newValue),
		).Else(
			clientv3.OpGet(key),
		).Commit()

		if err != nil {
			return err
		}

		if txnResp.Succeeded {
			return nil
		}
		// If the key was created while we were trying to create it, do the normal update proceedure

		origState = (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
	}

	for {
		if origState.Count == 0 {
			return errors.New("no record found")
		}

		newValue, err := mutateFunc(origState)
		if err != nil {
			return err
		}

		txnResp, err := etcd.KV.Txn(ctx).If(
			clientv3.Compare(clientv3.ModRevision(key), "=", origState.Kvs[0].ModRevision),
		).Then(
			clientv3.OpPut(key, newValue),
		).Else(
			clientv3.OpGet(key),
		).Commit()

		if err != nil {
			return err
		}

		if !txnResp.Succeeded {
			origState = (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
			log.Println("failed: ", origState)
			continue
		}

		return err
	}
}

func GetInitialData() (users []UserModel, devices []Device, err error) {
	txn := etcd.Txn(context.Background())
	txn.Then(clientv3.OpGet("users-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend)),
		clientv3.OpGet("devices-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend)))

	resp, err := txn.Commit()
	if err != nil {
		return nil, nil, err
	}

	for _, res := range resp.Responses[0].GetResponseRange().Kvs {
		var user UserModel
		err := json.Unmarshal(res.Value, &user)
		if err != nil {
			return nil, nil, err
		}

		users = append(users, user)
	}

	for _, res := range resp.Responses[1].GetResponseRange().Kvs {
		var device Device
		err := json.Unmarshal(res.Value, &device)
		if err != nil {
			return nil, nil, err
		}

		devices = append(devices, device)
	}

	return
}

func Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	resp, err := etcd.Get(ctx, key)
	cancel()
	if err != nil {
		return nil, err
	}

	if resp.Count == 0 {
		return nil, fs.ErrNotExist
	}

	return resp.Kvs[0].Value, nil
}

func Put(key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	_, err := etcd.Put(ctx, key, value)
	cancel()

	return err
}
