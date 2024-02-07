package data

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data/migrations"
	"github.com/NHAS/wag/pkg/fsops"
	_ "github.com/mattn/go-sqlite3"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
	"go.etcd.io/etcd/server/v3/embed"
)

// TODO Most of the methods in this package need to change to prevent race conditions from breaking the cluster
// The way we're going to do this is each get method will return the etcd key revision. If a user tries to make a change using an older revision then that will be an error
// Or a prompt on the admin ui

var (
	etcd                   *clientv3.Client
	etcdServer             *embed.Etcd
	allowedTokenCharacters = regexp.MustCompile(`[a-zA-Z0-9\-\_\.]+`)
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

func Load(path string) error {

	doMigration := true
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		doMigration = false
	}

	var db *sql.DB
	if doMigration {
		db, _ = sql.Open("sqlite3", path)

		defer db.Close()

		can, err := migrations.Can(db)
		if err != nil {
			return err
		}

		if can && !strings.HasPrefix(path, "file::memory:") && !strings.Contains(path, "mode=memory") {
			backupPath := path + "." + time.Now().Format("20060102150405") + ".bak"
			log.Println("can do migrations, backing up database to ", backupPath)

			err := fsops.CopyFile(path, backupPath)
			if err != nil {
				return err
			}
		}

		err = migrations.Do(db)
		if err != nil {
			return err
		}
	}

	part, err := generateRandomBytes(10)
	if err != nil {
		return err
	}
	etcdUnixSocket := "unix:///tmp/wag.etcd." + part

	cfg := embed.NewConfig()
	cfg.Name = config.Values.Clustering.Name
	cfg.ClusterState = config.Values.Clustering.ClusterState
	cfg.InitialClusterToken = "wag-test"
	cfg.LogLevel = config.Values.Clustering.ETCDLogLevel
	cfg.ListenPeerUrls = parseUrls(config.Values.Clustering.ListenAddresses...)
	cfg.ListenClientUrls = parseUrls(etcdUnixSocket)
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls

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

	cfg.Dir = filepath.Join(config.Values.Clustering.DatabaseLocation, config.Values.Clustering.Name+".wag-node.etcd")
	etcdServer, err = embed.StartEtcd(cfg)
	if err != nil {
		return err
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

	if doMigration {
		// This will be kept for 2 major releases with reduced support.
		// It is a no-op if a migration has already taken place
		err = migrateFromSql(db)
		if err != nil {
			return err
		}
	}

	// This will stay, so that the config can be used to easily spin up a new wag instance.
	// After first run this will be a no-op
	err = loadInitialSettings()
	if err != nil {
		return err
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

	response, err = etcd.Get(context.Background(), "wag-groups-", clientv3.WithPrefix())
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no groups found in database, importing from .json file (from this point the json file will be ignored)")

		// User to groups
		rGroupLookup := map[string]map[string]bool{}

		for groupName, members := range config.Values.Acls.Groups {
			groupJson, _ := json.Marshal(members)
			_, err = etcd.Put(context.Background(), "wag-groups-"+groupName, string(groupJson))
			if err != nil {
				return err
			}

			for _, user := range members {
				if rGroupLookup[user] == nil {
					rGroupLookup[user] = make(map[string]bool)
				}

				rGroupLookup[user][groupName] = true
			}
		}

		reverseMappingJson, _ := json.Marshal(rGroupLookup)
		_, err = etcd.Put(context.Background(), "wag-membership", string(reverseMappingJson))
		if err != nil {
			return err
		}
	}

	configData, _ := json.Marshal(config.Values)
	err = putIfNotFound(fullJsonConfigKey, string(configData), "full config")
	if err != nil {
		return err
	}

	err = putIfNotFound(helpMailKey, config.Values.HelpMail, "help mail")
	if err != nil {
		return err
	}

	err = putIfNotFound(externalAddressKey, config.Values.ExternalAddress, "external wag address")
	if err != nil {
		return err
	}

	err = putIfNotFound(dnsKey, config.Values.Wireguard.DNS, "dns")
	if err != nil {
		return err
	}

	err = putIfNotFound(InactivityTimeoutKey, config.Values.SessionInactivityTimeoutMinutes, "inactivity timeout")
	if err != nil {
		return err
	}

	err = putIfNotFound(SessionLifetimeKey, config.Values.MaxSessionLifetimeMinutes, "max session life")
	if err != nil {
		return err
	}

	err = putIfNotFound(LockoutKey, config.Values.Lockout, "lockout")
	if err != nil {
		return err
	}

	err = putIfNotFound(IssuerKey, config.Values.Authenticators.Issuer, "issuer name")
	if err != nil {
		return err
	}

	err = putIfNotFound(DomainKey, config.Values.Authenticators.DomainURL, "domain url")
	if err != nil {
		return err
	}

	err = putIfNotFound(defaultWGFileNameKey, config.Values.DownloadConfigFileName, "wireguard config file")
	if err != nil {
		return err
	}

	err = putIfNotFound(checkUpdatesKey, config.Values.CheckUpdates, "update check settings")
	if err != nil {
		return err
	}

	err = putIfNotFound(MFAMethodsEnabledKey, config.Values.Authenticators.Methods, "authorisation methods")
	if err != nil {
		return err
	}

	err = putIfNotFound(DefaultMFAMethodKey, config.Values.Authenticators.DefaultMethod, "default mfa method")
	if err != nil {
		return err
	}

	err = putIfNotFound(OidcDetailsKey, config.Values.Authenticators.OIDC, "oidc settings")
	if err != nil {
		return err
	}

	err = putIfNotFound(PamDetailsKey, config.Values.Authenticators.PAM, "pam settings")
	if err != nil {
		return err
	}

	return nil
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

func migrateFromSql(database *sql.DB) error {
	response, err := etcd.Get(context.Background(), "wag-migrated-sql")
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {

		log.Println("Doing migration to etcd from sqlite3")

		devices, err := sqlGetAllDevices(database)
		if err != nil {
			return err
		}

		for _, device := range devices {
			_, err := SetDevice(device.Username, device.Address, device.Publickey, device.PresharedKey)
			if err != nil {
				return err
			}
		}
		log.Println("Migrated", len(devices), "devices")

		adminUsers, err := sqlgetAllAdminUsers(database)
		if err != nil {
			return err
		}

		for _, admin := range adminUsers {
			err := CreateAdminUser(admin.Username, "aaaaaaaaaaaaaaaaaaa", false)
			if err != nil {
				return err
			}

			err = setAdminHash(admin.Username, admin.Hash)
			if err != nil {
				return err
			}

			if admin.Attempts > 5 {
				err := SetAdminUserLock(admin.Username)
				if err != nil {
					return err
				}
			}

		}
		log.Println("Migrated", len(adminUsers), "admin users")

		users, err := sqlGetAllUsers(database)
		if err != nil {
			return err
		}

		for _, user := range users {
			_, err := CreateUserDataAccount(user.Username)
			if err != nil {
				return err
			}

			if user.Locked {
				err = SetUserLock(user.Username)
				if err != nil {
					return err
				}
			}

			err = SetUserMfa(user.Username, user.Mfa, user.MfaType)
			if err != nil {
				return err
			}

			if user.Enforcing {
				err = SetEnforceMFAOn(user.Username)
			} else {
				err = SetEnforceMFAOff(user.Username)
			}
			if err != nil {
				return err
			}

		}
		log.Println("Migrated", len(users), "users")

		tokens, err := sqlGetRegistrationTokens(database)
		if err != nil {
			return err
		}

		for _, token := range tokens {
			err := AddRegistrationToken(token.Token, token.Username, token.Overwrites, token.Groups, token.NumUses)
			if err != nil {
				return err
			}
		}

		_, err = etcd.Put(context.Background(), "wag-migrated-sql", "done!")
		if err != nil {
			return err
		}

		log.Println("Migrated", len(tokens), "registration tokens")

	}

	return nil
}

func TearDown() {
	if etcdServer != nil {
		log.Println("Tearing down server")
		etcdServer.Close()
	}
}

func doSafeUpdate(ctx context.Context, key string, mutateFunc func(*clientv3.GetResponse) (value string, err error)) error {
	//https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L382
	opts := []clientv3.OpOption{}

	if mutateFunc == nil {
		return errors.New("no mutate function set in safe update")
	}

	origState, err := etcd.Get(ctx, key, opts...)
	if err != nil {
		return err
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
