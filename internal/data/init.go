package data

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data/migrations"
	"github.com/NHAS/wag/pkg/fsops"
	_ "github.com/mattn/go-sqlite3"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

var (
	database               *sql.DB
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

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	database = db

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

	cfg := embed.NewConfig()
	cfg.Name = config.Values().Clustering.Name
	cfg.InitialClusterToken = "wag-test"
	cfg.LogLevel = "error"
	cfg.ListenPeerUrls = parseUrls(config.Values().Clustering.ListenAddresses...)
	cfg.ListenClientUrls = parseUrls("http://127.0.0.1:2480")
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls

	if _, ok := config.Values().Clustering.Peers[cfg.Name]; ok {
		return fmt.Errorf("clustering.peers contains the same name (%s) as this node this would trample something and break", cfg.Name)
	}

	peers := config.Values().Clustering.Peers
	peers[cfg.Name] = config.Values().Clustering.ListenAddresses

	cfg.InitialCluster = ""
	for tag, addresses := range peers {
		cfg.InitialCluster += fmt.Sprintf("%s=%s", tag, strings.Join(addresses, ","))
	}

	cfg.Dir = filepath.Join(config.Values().Clustering.DatabaseLocation, config.Values().Clustering.Name+".wag-node.etcd")
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

	log.Println("Connecting to etcd")

	etcd, err = clientv3.New(clientv3.Config{
		Endpoints:   []string{"127.0.0.1:2480"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}

	response, err := etcd.Get(context.Background(), "wag-migrated-sql")
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {

		log.Println("Doing migration to etcd from sqlite3")

		devices, err := sqlGetAllDevices()
		if err != nil {
			return err
		}

		for _, device := range devices {
			_, err := AddDevice(device.Username, device.Address, device.Publickey, device.PresharedKey)
			if err != nil {
				return err
			}
		}
		log.Println("Migrated", len(devices), "devices")

		adminUsers, err := sqlgetAllAdminUsers()
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

		users, err := sqlGetAllUsers()
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

		tokens, err := sqlGetRegistrationTokens()
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

	response, err = etcd.Get(context.Background(), "wag-acls")
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no acls found in database, importing from .json file (from this point the json file will be ignored)")

		for aclName, acl := range config.Values().Acls.Policies {
			aclJson, _ := json.Marshal(acl)
			_, err = etcd.Put(context.Background(), "wag-acls-"+aclName, string(aclJson))
			if err != nil {
				return err
			}
		}
	}

	response, err = etcd.Get(context.Background(), "wag-groups")
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no groups found in database, importing from .json file (from this point the json file will be ignored)")

		for groupName, group := range config.Values().Acls.Groups {
			groupJson, _ := json.Marshal(group)
			_, err = etcd.Put(context.Background(), "wag-groups-"+groupName, string(groupJson))
			if err != nil {
				return err
			}
		}
	}

	response, err = etcd.Get(context.Background(), "wag-config")
	if err != nil {
		return err
	}

	if len(response.Kvs) == 0 {
		log.Println("no config found in database, importing from .json file (from this point the json file will be ignored)")

		groups, _ := json.Marshal(config.Values())
		_, err = etcd.Put(context.Background(), "wag-config", string(groups))
		if err != nil {
			return err
		}
	}

	go checkClusterHealth()
	go watchEvents()

	return nil
}

func TearDown() {
	if etcdServer != nil {
		etcdServer.Close()
	}
}

func watchEvents() {
	wc := etcd.Watch(context.Background(), "", clientv3.WithPrefix(), clientv3.WithCreatedNotify())
	for watchEvent := range wc {

		for _, event := range watchEvent.Events {

			switch {
			case bytes.HasPrefix(event.Kv.Key, []byte("devices-")):

			case bytes.HasPrefix(event.Kv.Key, []byte("users-")):

			default:
				continue
			}

		}

	}
}

func checkClusterHealth() {
	startup := true
	for {
		leader := etcdServer.Server.Leader()
		if leader == 0 {

			if startup {
				// When we first start up, make sure we wait for an election to either have occured, or is occuring before we check to make sure things are still up
				time.Sleep(etcdServer.Server.Cfg.ElectionTimeout() * 2)
				continue
			}

			select {
			case <-etcdServer.Server.LeaderChangedNotify():
				// Something has changed, so try and check whats going on
				continue
			case <-time.After(30 * time.Second):
				// Do a random recheck just for fun
				continue
			case <-time.After(etcdServer.Server.Cfg.ElectionTimeout() * 2):
				// Dead
				log.Println("Cluster is no longer contactable. Shutting wag down and entering degraded state")

			}
		}

		startup = false
	}
}

func doSafeUpdate(ctx context.Context, key string, prefix bool, mutateFunc func(*clientv3.GetResponse) (value string, onErrwrite bool, err error)) error {
	//https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/storage/etcd3/store.go#L382
	opts := []clientv3.OpOption{}
	if prefix {
		opts = append(opts, clientv3.WithPrefix())
	}

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

		newValue, onErrwrite, err := mutateFunc(origState)
		if err != nil && !onErrwrite {
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
