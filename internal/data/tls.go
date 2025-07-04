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

	"github.com/caddyserver/certmagic"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	AcmeKey                     = "wag-acme-"
	AcmeEmailKey                = AcmeKey + "email"
	AcmeProviderKey             = AcmeKey + "provider"
	AcmeDNS01CloudflareAPIToken = AcmeKey + "dns01-cloudflare"
)

type CloudflareToken struct {
	APIToken string `json:"api_token" sensitive:"true"`
}

func GetAcmeDNS01CloudflareToken() (CloudflareToken, error) {
	return get[CloudflareToken](AcmeDNS01CloudflareAPIToken)
}

func SetAcmeDNS01CloudflareToken(token string) error {
	var newToken CloudflareToken
	newToken.APIToken = token

	return set(AcmeDNS01CloudflareAPIToken, true, newToken)
}

func GetAcmeEmail() (string, error) {
	return get[string](AcmeEmailKey)
}

func SetAcmeEmail(email string) error {

	// allow unsetting value
	if email != "" {
		_, err := mail.ParseAddress(email)
		if err != nil {
			return err
		}
	}

	return set(AcmeEmailKey, true, email)
}

func SetAcmeProvider(providerURL string) error {

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

	return set(AcmeProviderKey, true, providerURL)
}

func GetAcmeProvider() (string, error) {
	return get[string](AcmeProviderKey)
}

type CertMagicStore struct {
	basePath string
	locks    map[string]*concurrency.Mutex
	mapMutex *sync.RWMutex
}

func NewCertStore(basePath string) *CertMagicStore {
	if !strings.HasPrefix(basePath, string(os.PathSeparator)) {
		basePath = string(os.PathSeparator) + basePath
	}

	c := &CertMagicStore{
		basePath: basePath,
		locks:    make(map[string]*concurrency.Mutex),
		mapMutex: &sync.RWMutex{},
	}

	return c
}

func (cms *CertMagicStore) Exists(ctx context.Context, key string) bool {
	keyPath := path.Join(cms.basePath, key)

	res, err := etcd.Get(ctx, keyPath, clientv3.WithCountOnly())
	if err != nil {
		return false
	}

	return res.Count > 1
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

	session, err := concurrency.NewSession(etcd, concurrency.WithContext(ctx))
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

	_, err := etcd.Put(ctx, keyPath, string(value))
	return err
}

func (cms *CertMagicStore) Load(ctx context.Context, key string) ([]byte, error) {
	keyPath := path.Join(cms.basePath, key)

	res, err := etcd.Get(ctx, keyPath)
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

	delResp, err := etcd.Delete(ctx, keyPath)
	if err != nil {

		return err
	}

	if delResp.Deleted == 0 {

		if !strings.HasSuffix(keyPath, string(os.PathSeparator)) {
			keyPath = keyPath + string(os.PathSeparator)
		}

		delResp, err := etcd.Delete(ctx, keyPath, clientv3.WithPrefix())
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

	response, err := etcd.Get(context.Background(), keyPath, clientv3.WithPrefix(), clientv3.WithKeysOnly())
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
	for _, key := range keys {
		// prefix/dir1/file1 -> dir1/file1
		noPrefixKey := strings.TrimPrefix(key, pathPrefix+"/")
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

	res, err := etcd.Get(ctx, keyPath)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	r := certmagic.KeyInfo{
		Key: key,
	}

	if len(res.Kvs) > 1 {

		r.Size = int64(len(res.Kvs[0].Value))
		r.IsTerminal = true

		return r, nil
	}

	// look for directory
	res, err = etcd.Get(ctx, keyPath+string(os.PathSeparator), clientv3.WithPrefix(), clientv3.WithCountOnly(), clientv3.WithKeysOnly())
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	if res.Count == 0 {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}

	r.IsTerminal = false

	return r, nil
}
