package data

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/autoetcdtls/manager"
	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/queue"
	_ "github.com/mattn/go-sqlite3"
	"go.etcd.io/etcd/client/pkg/v3/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

const (
	NodeInfo   = "wag/node/"
	NodeErrors = "wag/node/errors"
)

const (
	dbMigrations = "wag-db-migrations"
)

var (
	allowedTokenCharacters = regexp.MustCompile(`[a-zA-Z0-9\-\_\.]+`)
	TLSManager             *manager.Manager
)

type database struct {
	etcd       *clientv3.Client
	etcdServer *embed.Etcd

	contextMaps map[string]context.CancelFunc

	clusterHealthLck       sync.RWMutex
	clusterHealthListeners map[string]func(string)

	eventsQueue *queue.Queue[GeneralEvent]
	exit        chan bool

	id types.ID
}

func (d *database) parseUrls(values ...string) []url.URL {
	urls := make([]url.URL, 0, len(values))
	for _, s := range values {
		u, err := url.Parse(s)
		if err != nil {
			log.Error().Err(err).Msg("Invalid URL")
			continue
		}
		urls = append(urls, *u)
	}
	return urls
}

func Load(joinToken string, testing bool) (db *database, err error) {

	db = &database{
		contextMaps: map[string]context.CancelFunc{},

		clusterHealthListeners: map[string]func(string){},

		eventsQueue: queue.NewQueue[GeneralEvent](40),
		exit:        make(chan bool),
	}

	if config.Values.RemoteCluster != nil {

		idBytes := make([]byte, 8)
		_, err := rand.Read(idBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ID: %w", err)
		}

		db.id = types.ID(binary.BigEndian.Uint64(idBytes))
		config, err := clientv3.NewClientConfig(config.Values.RemoteCluster, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to make etcd client connection: %w", err)
		}

		db.etcd, err = clientv3.New(*config)
		if err != nil {
			return nil, err
		}

		if err := db.doMigrations(); err != nil {
			return nil, err
		}

		err = db.loadInitialSettings()
		if err != nil {
			return nil, err
		}

		return db, nil
	}

	if TLSManager == nil {
		if joinToken == "" {
			TLSManager, err = manager.New(config.Values.Clustering.TLSManagerStorage, config.Values.Clustering.TLSManagerListenURL)
			if err != nil {
				return nil, fmt.Errorf("tls manager: %w", err)
			}
		} else {

			if config.Values.Clustering.TLSManagerStorage == "" {
				config.Values.Clustering.TLSManagerStorage = "certificates"
			}

			TLSManager, err = manager.Join(joinToken, config.Values.Clustering.TLSManagerStorage, map[string]func(name string, data string){
				"config.json": func(name, data string) {
					err := os.WriteFile("config.json", []byte(data), 0600)
					if err != nil {
						log.Fatal().Err(err).Msg("failed to create config.json from other cluster members config")
					}

					log.Info().Msg("got additional, loading config file")
					err = config.Load("config.json")
					if err != nil {
						log.Fatal().Err(err).Msg("config supplied by other cluster member was invalid (potential version issues?)")
					}
				},
			})
			if err != nil {
				return nil, err
			}
		}
	}

	part, err := utils.GenerateRandomHex(10)
	if err != nil {
		return nil, err
	}
	etcdUnixSocket := "unix:///tmp/wag.d.etcd." + part

	cfg := embed.NewConfig()
	cfg.Name = config.Values.Clustering.Name
	if testing {
		cfg.Name += part
	}
	cfg.ClusterState = config.Values.Clustering.ClusterState
	cfg.InitialClusterToken = "wag"
	cfg.LogLevel = config.Values.Clustering.ETCDLogLevel
	cfg.ListenPeerUrls = db.parseUrls(config.Values.Clustering.ListenAddresses...)
	cfg.ListenClientUrls = db.parseUrls(etcdUnixSocket)
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls
	// this was changed in wag 9.0.1
	// this effectively means we can guarantee that when we use PrevKV that we will have a previous key value thus we can simplify the events watcher
	// this will cause the compactor to run every 5 mins which may result in higher disk usage, but keeping a smaller number of keys should mean less work is done overall
	cfg.AutoCompactionMode = "revision"
	cfg.AutoCompactionRetention = "3"
	cfg.SnapshotCount = 50000

	cfg.PeerTLSInfo.ClientCertAuth = true
	cfg.PeerTLSInfo.TrustedCAFile = TLSManager.GetCACertPath()
	cfg.PeerTLSInfo.CertFile = TLSManager.GetPeerCertPath()
	cfg.PeerTLSInfo.KeyFile = TLSManager.GetPeerKeyPath()

	if _, ok := config.Values.Clustering.Peers[cfg.Name]; ok {
		return nil, fmt.Errorf("clustering.peers contains the same name (%s) as this node this would trample something and break", cfg.Name)
	}

	peers := config.Values.Clustering.Peers
	peers[cfg.Name] = config.Values.Clustering.ListenAddresses

	cfg.InitialCluster = ""
	for tag, addresses := range peers {
		cfg.InitialCluster += fmt.Sprintf("%s=%s", tag, strings.Join(addresses, ",")) + ","
	}

	cfg.InitialCluster = cfg.InitialCluster[:len(cfg.InitialCluster)-1]

	cfg.Dir = filepath.Join(config.Values.Clustering.DatabaseLocation, cfg.Name+".wag-node.etcd")
	db.etcdServer, err = embed.StartEtcd(cfg)
	if err != nil {
		return nil, fmt.Errorf("error starting etcd: %s", err)
	}

	select {
	case <-db.etcdServer.Server.ReadyNotify():
		break
	case <-time.After(60 * time.Second):
		db.etcdServer.Server.Stop() // trigger a shutdown
		return nil, errors.New("etcd took too long to start")
	}

	db.etcd, err = clientv3.New(clientv3.Config{
		Endpoints: []string{etcdUnixSocket},
	})
	if err != nil {
		return nil, err
	}

	log.Info().Msg("Successfully connected to etcd")

	if !db.etcdServer.Server.IsLearner() {

		// ugh duplicated code
		if err := db.doMigrations(); err != nil {
			return nil, err
		}

		// After first run this will be a no-op
		err = db.loadInitialSettings()
		if err != nil {
			return nil, err
		}

	}

	go db.checkClusterHealth()

	return db, nil
}

func (d *database) GetEventQueue() []GeneralEvent {
	return d.eventsQueue.ReadAll()
}

func (d *database) Raw() *clientv3.Client {
	return d.etcd
}

func (d *database) doMigrations() error {
	type migration struct {
		version string
		run     func() error
	}

	return nil
}

func (d *database) loadInitialSettings() error {

	loadedDocument, err := json.Marshal(config.Values)
	if err != nil {
		return err
	}

	ConfigDiffer.Plan(context.Background())

	return nil
}

func (d *database) readTLSPems(cert, key string) (string, string, error) {

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

func (d *database) TearDown() error {
	close(d.exit)

	if d.etcd != nil {
		d.etcd.Close()
		d.etcd = nil

	}

	if d.etcdServer != nil {
		d.etcdServer.Close()
		d.etcdServer = nil
	}

	return nil
}

func (d *database) GetInitialData() (usersEntries []config.UserModel, devicesEntries []config.Device, err error) {

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()
	usersHandle := tetcd.ListTx(then, InternalConfig.Users())
	devicesHandle := tetcd.DynamicCollectionTx(then, InternalConfig.Devices.Machines())

	if err := txn.Commit(); err != nil {
		return nil, nil, err
	}

	users, err := usersHandle.Entries()
	if err != nil {
		return nil, nil, err
	}

	usersEntries = make([]config.UserModel, 0, len(users))
	for _, usermodel := range users {
		usersEntries = append(usersEntries, usermodel)
	}

	devices, err := devicesHandle.Entries()
	if err != nil {
		return nil, nil, err
	}

	devicesEntries = make([]config.Device, 0, len(devices))
	for _, userDevices := range devices {
		for _, device := range userDevices {
			devicesEntries = append(devicesEntries, device)
		}
	}

	return usersEntries, devicesEntries, nil
}

func (d *database) Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	resp, err := d.etcd.Get(ctx, key)
	cancel()
	if err != nil {
		return nil, err
	}

	if resp.Count == 0 {
		return nil, fs.ErrNotExist
	}

	return resp.Kvs[0].Value, nil
}

func (d *database) Put(key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	_, err := d.etcd.Put(ctx, key, value)
	cancel()

	return err
}

func (d *database) RegisterClusterHealthListener(f func(status string)) (string, error) {

	key, err := utils.GenerateRandomHex(16)
	if err != nil {
		return "", err
	}

	d.clusterHealthLck.Lock()
	d.clusterHealthListeners[key] = f
	d.clusterHealthLck.Unlock()

	if d.etcdServer != nil && !d.etcdServer.Server.IsLearner() || !d.ClusterManagementEnabled() {
		// The moment we've registered a new health listener, test the cluster so it gets a callback
		d.testCluster()
	}

	return key, nil
}

func (d *database) checkClusterHealth() {

	leaderMonitor := time.NewTicker(1 * time.Second)
	go func() {
		for range leaderMonitor.C {
			if d.etcdServer.Server.Leader() == 0 {

				d.notifyClusterHealthListeners("electing")
				time.Sleep(d.etcdServer.Server.Cfg.ElectionTimeout() * 2)

				if d.etcdServer.Server.Leader() == 0 {
					d.notifyClusterHealthListeners("dead")
				}
			}
		}
	}()

	clusterMonitor := time.NewTicker(30 * time.Second)
	go func() {
		for range clusterMonitor.C {
			// If we're a learner we cant write to the cluster, so just wait until we're promoted
			if !d.etcdServer.Server.IsLearner() {
				d.testCluster()
			}
		}
	}()

	<-d.exit

	log.Info().Msg("etcd server was instructed to terminate")

	leaderMonitor.Stop()
	clusterMonitor.Stop()

}

func (d *database) testCluster() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	_, err := d.etcd.Put(ctx, path.Join(NodeInfo, d.GetCurrentNodeID().String(), "ping"), time.Now().Format(time.RFC1123Z))
	cancel()
	if err != nil {
		log.Error().Err(err).Msg("unable to write liveness value")

		d.notifyClusterHealthListeners("dead")
		return
	}

	d.notifyHealthy()
}

func (d *database) notifyHealthy() {
	if d.etcdServer != nil && d.etcdServer.Server.IsLearner() {
		d.notifyClusterHealthListeners("learner")
	} else {
		d.notifyClusterHealthListeners("healthy")
	}
}

func (d *database) notifyClusterHealthListeners(event string) {
	d.clusterHealthLck.RLock()
	defer d.clusterHealthLck.RUnlock()

	for _, f := range d.clusterHealthListeners {
		go f(event)
	}
}
