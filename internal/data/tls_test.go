package data

// Adapted from https://github.com/pberkel/caddy-storage-Etcd/blob/main/storage_test.go

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"testing"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/stretchr/testify/assert"
)

const (
	testKeyCertPath    = "certificates"
	testKeyAcmePath    = testKeyCertPath + "/acme-v02.api.letsencrypt.org-directory"
	testKeyExamplePath = testKeyAcmePath + "/example.com"
	testKeyExampleCrt  = testKeyExamplePath + "/example.com.crt"
	testKeyExampleKey  = testKeyExamplePath + "/example.com.key"
	testKeyExampleJson = testKeyExamplePath + "/example.com.json"
	testKeyLock        = "locks/issue_cert_example.com"
)

var (
	testValueCrt  = []byte("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu")
	testValueKey  = []byte("RWdlc3RhcyBlZ2VzdGFzIGZyaW5naWxsYSBwaGFzZWxsdXMgZmF1Y2lidXMgc2NlbGVyaXNxdWUgZWxlaWZlbmQgZG9uZWMgcHJldGl1bSB2dWxwdXRhdGUuIFRpbmNpZHVudCBvcm5hcmUgbWFzc2EgZWdldC4=")
	testValueJson = []byte("U2FnaXR0aXMgYWxpcXVhbSBtYWxlc3VhZGEgYmliZW5kdW0gYXJjdSB2aXRhZSBlbGVtZW50dW0uIEludGVnZXIgbWFsZXN1YWRhIG51bmMgdmVsIHJpc3VzIGNvbW1vZG8gdml2ZXJyYSBtYWVjZW5hcy4=")
	rs            *CertMagicStore
)

func TestMain(m *testing.M) {

	if err := config.Load("../config/testing_config2.json"); err != nil {
		log.Println("failed to load config: ", err)
		os.Exit(1)
	}

	db, err := Load("", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	rs = NewCertStore(db.etcd, "wag-certificates")
}

func TestEtcdStorage_Store(t *testing.T) {

	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)
}

func TestEtcdStorage_Exists(t *testing.T) {

	exists := rs.Exists(context.Background(), testKeyExampleCrt)
	assert.False(t, exists)

	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)

	exists = rs.Exists(context.Background(), testKeyExampleCrt)
	assert.True(t, exists)
}

func TestEtcdStorage_Load(t *testing.T) {

	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)

	loadedValue, err := rs.Load(context.Background(), testKeyExampleCrt)
	assert.NoError(t, err)

	assert.Equal(t, testValueCrt, loadedValue)
}

func TestEtcdStorage_Delete(t *testing.T) {

	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), testKeyExampleCrt)
	assert.NoError(t, err)

	exists := rs.Exists(context.Background(), testKeyExampleCrt)
	assert.False(t, exists)

	loadedValue, err := rs.Load(context.Background(), testKeyExampleCrt)
	assert.Nil(t, loadedValue)

	notExist := errors.Is(err, fs.ErrNotExist)
	assert.True(t, notExist)
}

func TestEtcdStorage_Stat(t *testing.T) {

	size := int64(len(testValueCrt))

	startTime := time.Now()
	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	endTime := time.Now()
	assert.NoError(t, err)

	stat, err := rs.Stat(context.Background(), testKeyExampleCrt)
	assert.NoError(t, err)

	assert.Equal(t, testKeyExampleCrt, stat.Key)
	assert.WithinRange(t, stat.Modified, startTime, endTime)
	assert.Equal(t, size, stat.Size)
}

func TestEtcdStorage_List(t *testing.T) {

	// Store two key values
	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), testKeyExampleKey, testValueKey)
	assert.NoError(t, err)

	// List recursively from root
	keys, err := rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.NotContains(t, keys, testKeyExampleJson)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), testKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.NotContains(t, keys, testKeyExampleJson)

	// Store third key value
	err = rs.Store(context.Background(), testKeyExampleJson, testValueJson)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.Contains(t, keys, testKeyExampleJson)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), testKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.Contains(t, keys, testKeyExampleJson)

	// Delete one key value
	err = rs.Delete(context.Background(), testKeyExampleCrt)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.Contains(t, keys, testKeyExampleJson)

	keys, err = rs.List(context.Background(), testKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.Contains(t, keys, testKeyExampleJson)

	// Delete remaining two key values
	err = rs.Delete(context.Background(), testKeyExampleKey)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), testKeyExampleJson)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Empty(t, keys)

	keys, err = rs.List(context.Background(), testKeyCertPath, true)
	assert.NoError(t, err)
	assert.Empty(t, keys)
}

func TestEtcdStorage_ListNonRecursive(t *testing.T) {

	// Store three key values
	err := rs.Store(context.Background(), testKeyExampleCrt, testValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), testKeyExampleKey, testValueKey)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), testKeyExampleJson, testValueJson)
	assert.NoError(t, err)

	// List non-recursively from root
	keys, err := rs.List(context.Background(), "", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, testKeyCertPath)

	// List non-recursively from first level
	keys, err = rs.List(context.Background(), testKeyCertPath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, testKeyAcmePath)

	// List non-recursively from second level
	keys, err = rs.List(context.Background(), testKeyAcmePath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, testKeyExamplePath)

	// List non-recursively from third level
	keys, err = rs.List(context.Background(), testKeyExamplePath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, testKeyExampleCrt)
	assert.Contains(t, keys, testKeyExampleKey)
	assert.Contains(t, keys, testKeyExampleJson)
}

func TestEtcdStorage_LockUnlock(t *testing.T) {

	err := rs.Lock(context.Background(), testKeyLock)
	assert.NoError(t, err)

	err = rs.Unlock(context.Background(), testKeyLock)
	assert.NoError(t, err)
}
