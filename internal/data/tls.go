package data

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/NHAS/wag/internal/config"
	"github.com/caddyserver/certmagic"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func (d *database) GetAcmeDNS01CloudflareToken() (config.CloudflareToken, error) {
	return Config.Webserver.Acme.CloudflareDNSToken().Get(context.Background(), d.etcd)
}

func (d *database) SetAcmeDNS01CloudflareToken(token string) error {
	var newToken config.CloudflareToken
	newToken.APIToken = token

	return Config.Webserver.Acme.CloudflareDNSToken().Put(context.Background(), d.etcd, newToken)
}

func (d *database) GetAcmeEmail() (string, error) {
	return Config.Webserver.Acme.Email().Get(context.Background(), d.etcd)
}

func (d *database) SetAcmeEmail(email string) error {

	// allow unsetting value
	if email != "" {
		_, err := mail.ParseAddress(email)
		if err != nil {
			return err
		}
	}

	return Config.Webserver.Acme.Email().Put(context.Background(), d.etcd, email)
}

func (d *database) SetAcmeProvider(providerURL string) error {

	// we're allowing users to unset a provider url
	if providerURL != "" {
		u, err := url.ParseRequestURI(providerURL)
		if err != nil {
			return fmt.Errorf("invalid acme provider url: %w", err)
		}

		if u.Scheme != "https" {
			return errors.New("acme provider must start with https://")
		}

		if u.Host == "" {
			return errors.New("invalid hostname in provider url")
		}
	}

	return Config.Webserver.Acme.CAProvider().Put(context.Background(), d.etcd, providerURL)
}

func (d *database) GetAcmeProvider() (string, error) {
	return Config.Webserver.Acme.CAProvider().Get(context.Background(), d.etcd)
}

type CertMagicStore struct {
	basePath string
	locks    map[string]*concurrency.Mutex
	mapMutex *sync.RWMutex
	etcd     *clientv3.Client
}

func NewCertStore(etcd *clientv3.Client, basePath string) *CertMagicStore {
	if !strings.HasPrefix(basePath, string(os.PathSeparator)) {
		basePath = string(os.PathSeparator) + basePath
	}

	c := &CertMagicStore{
		etcd:     etcd,
		basePath: basePath,
		locks:    make(map[string]*concurrency.Mutex),
		mapMutex: &sync.RWMutex{},
	}

	return c
}

func (cms *CertMagicStore) Exists(ctx context.Context, key string) bool {
	keyPath := path.Join(cms.basePath, key)

	res, err := cms.etcd.Get(ctx, keyPath, clientv3.WithCountOnly(), clientv3.WithPrefix())

	if err != nil {
		return false
	}

	return res.Count > 0
}

func (cms *CertMagicStore) lockPath(name string) string {
	return path.Join(cms.basePath, "locks", certmagic.StorageKeys.Safe(name)+"-lock")
}

func (cms *CertMagicStore) Lock(ctx context.Context, name string) error {
	lockKey := cms.lockPath(name)

	cms.mapMutex.RLock()
	_, lockExists := cms.locks[lockKey]
	cms.mapMutex.RUnlock()
	if lockExists {

		return nil
	}

	session, err := concurrency.NewSession(cms.etcd, concurrency.WithContext(ctx))
	if err != nil {

		return err
	}

	mutex := concurrency.NewMutex(session, lockKey)
	err = mutex.Lock(session.Client().Ctx())
	if err != nil {

		return err
	}

	cms.mapMutex.Lock()
	cms.locks[lockKey] = mutex
	cms.mapMutex.Unlock()

	return nil
}

func (cms *CertMagicStore) Unlock(ctx context.Context, name string) error {
	lockKey := cms.lockPath(name)

	cms.mapMutex.RLock()
	mutex, ok := cms.locks[lockKey]
	cms.mapMutex.RUnlock()
	if !ok {
		return errors.New("mutex is not held")
	}

	defer func() {
		cms.mapMutex.Lock()
		delete(cms.locks, lockKey)
		cms.mapMutex.Unlock()
	}()

	return mutex.Unlock(ctx)
}

func (cms *CertMagicStore) Store(ctx context.Context, key string, value []byte) error {
	keyPath := path.Join(cms.basePath, key)

	_, err := cms.etcd.Put(ctx, keyPath, string(value))

	return err
}

func (cms *CertMagicStore) Load(ctx context.Context, key string) ([]byte, error) {
	keyPath := path.Join(cms.basePath, key)

	res, err := cms.etcd.Get(ctx, keyPath)

	if err != nil {
		return nil, err
	}

	if res.Count == 0 {
		return nil, fs.ErrNotExist
	}

	if len(res.Kvs) == 0 {
		return nil, fs.ErrNotExist
	}

	return res.Kvs[0].Value, nil
}

func (cms *CertMagicStore) Delete(ctx context.Context, key string) error {

	keyPath := path.Join(cms.basePath, key)

	delResp, err := cms.etcd.Delete(ctx, keyPath)

	if err != nil {

		return err
	}

	if delResp.Deleted == 0 {

		if !strings.HasSuffix(keyPath, string(os.PathSeparator)) {
			keyPath = keyPath + string(os.PathSeparator)
		}

		delResp, err := cms.etcd.Delete(ctx, keyPath, clientv3.WithPrefix())

		if err != nil {
			return err
		}

		if delResp.Deleted == 0 {

			return fs.ErrNotExist
		}

	}

	return nil
}

func (cms *CertMagicStore) List(ctx context.Context, pathPrefix string, recursive bool) ([]string, error) {

	keyPath := path.Join(cms.basePath, pathPrefix)

	response, err := cms.etcd.Get(context.Background(), keyPath, clientv3.WithPrefix(), clientv3.WithKeysOnly())

	if err != nil {
		return nil, err
	}

	if response.Count == 0 {
		return nil, fs.ErrNotExist
	}

	var keys []string
	for _, res := range response.Kvs {

		key := strings.TrimPrefix(string(res.Key), cms.basePath+string(os.PathSeparator))
		keys = append(keys, key)
	}

	if recursive {
		return keys, nil
	}

	// stolen from: https://github.com/SUNET/knubbis-fleetlock/blob/main/certmagic/etcd3storage/etcd3storage.go

	combinedKeys := map[string]struct{}{}
	stripPrefix := pathPrefix
	if !strings.HasSuffix(pathPrefix, "/") {
		stripPrefix += "/"
	}
	for _, key := range keys {
		// prefix/dir1/file1 -> dir1/file1

		noPrefixKey := strings.TrimPrefix(key, stripPrefix)
		// dir1/file1 -> dir1
		part := strings.Split(noPrefixKey, "/")[0]
		combinedKeys[part] = struct{}{}
	}

	cKeys := []string{}
	for key := range combinedKeys {
		cKeys = append(cKeys, path.Join(pathPrefix, key))
	}

	return cKeys, nil
}

func (cms *CertMagicStore) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {

	keyPath := path.Join(cms.basePath, key)
	res, err := cms.etcd.Get(ctx, keyPath)

	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	r := certmagic.KeyInfo{
		Key: key,
	}

	if len(res.Kvs) > 0 {

		r.Size = int64(len(res.Kvs[0].Value))
		r.IsTerminal = true

		return r, nil
	}

	// look for directory
	res, err = cms.etcd.Get(ctx, keyPath+string(os.PathSeparator), clientv3.WithPrefix(), clientv3.WithCountOnly(), clientv3.WithKeysOnly())

	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	if res.Count == 0 {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}

	r.IsTerminal = false

	return r, nil
}
