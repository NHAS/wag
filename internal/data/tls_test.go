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
	TestDB            = 9
	TestKeyPrefix     = "etctlstest"
	TestEncryptionKey = "1aedfs5kcM8lOZO3BDDMuwC23croDwRr"
	TestCompression   = true

	TestKeyCertPath       = "certificates"
	TestKeyAcmePath       = TestKeyCertPath + "/acme-v02.api.letsencrypt.org-directory"
	TestKeyExamplePath    = TestKeyAcmePath + "/example.com"
	TestKeyExampleCrt     = TestKeyExamplePath + "/example.com.crt"
	TestKeyExampleKey     = TestKeyExamplePath + "/example.com.key"
	TestKeyExampleJson    = TestKeyExamplePath + "/example.com.json"
	TestKeyLock           = "locks/issue_cert_example.com"
	TestKeyLockIterations = 250
)

var (
	TestValueCrt  = []byte("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu")
	TestValueKey  = []byte("RWdlc3RhcyBlZ2VzdGFzIGZyaW5naWxsYSBwaGFzZWxsdXMgZmF1Y2lidXMgc2NlbGVyaXNxdWUgZWxlaWZlbmQgZG9uZWMgcHJldGl1bSB2dWxwdXRhdGUuIFRpbmNpZHVudCBvcm5hcmUgbWFzc2EgZWdldC4=")
	TestValueJson = []byte("U2FnaXR0aXMgYWxpcXVhbSBtYWxlc3VhZGEgYmliZW5kdW0gYXJjdSB2aXRhZSBlbGVtZW50dW0uIEludGVnZXIgbWFsZXN1YWRhIG51bmMgdmVsIHJpc3VzIGNvbW1vZG8gdml2ZXJyYSBtYWVjZW5hcy4=")
)

func TestMain(m *testing.M) {

	if err := config.Load("../config/testing_config.json"); err != nil {
		log.Println("failed to load config: ", err)
		os.Exit(1)
	}

	err := Load("data_testing", "", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func TestEtcdStorage_Store(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)
}

func TestEtcdStorage_Exists(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	exists := rs.Exists(context.Background(), TestKeyExampleCrt)
	assert.False(t, exists)

	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)

	exists = rs.Exists(context.Background(), TestKeyExampleCrt)
	assert.True(t, exists)
}

func TestEtcdStorage_Load(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)

	loadedValue, err := rs.Load(context.Background(), TestKeyExampleCrt)
	assert.NoError(t, err)

	assert.Equal(t, TestValueCrt, loadedValue)
}

func TestEtcdStorage_Delete(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), TestKeyExampleCrt)
	assert.NoError(t, err)

	exists := rs.Exists(context.Background(), TestKeyExampleCrt)
	assert.False(t, exists)

	loadedValue, err := rs.Load(context.Background(), TestKeyExampleCrt)
	assert.Nil(t, loadedValue)

	notExist := errors.Is(err, fs.ErrNotExist)
	assert.True(t, notExist)
}

func TestEtcdStorage_Stat(t *testing.T) {

	rs := NewCertStore("wag-certificates")
	size := int64(len(TestValueCrt))

	startTime := time.Now()
	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	endTime := time.Now()
	assert.NoError(t, err)

	stat, err := rs.Stat(context.Background(), TestKeyExampleCrt)
	assert.NoError(t, err)

	assert.Equal(t, TestKeyExampleCrt, stat.Key)
	assert.WithinRange(t, stat.Modified, startTime, endTime)
	assert.Equal(t, size, stat.Size)
}

func TestEtcdStorage_List(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	// Store two key values
	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), TestKeyExampleKey, TestValueKey)
	assert.NoError(t, err)

	// List recursively from root
	keys, err := rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.NotContains(t, keys, TestKeyExampleJson)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), TestKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.NotContains(t, keys, TestKeyExampleJson)

	// Store third key value
	err = rs.Store(context.Background(), TestKeyExampleJson, TestValueJson)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.Contains(t, keys, TestKeyExampleJson)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), TestKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.Contains(t, keys, TestKeyExampleJson)

	// Delete one key value
	err = rs.Delete(context.Background(), TestKeyExampleCrt)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.Contains(t, keys, TestKeyExampleJson)

	keys, err = rs.List(context.Background(), TestKeyCertPath, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.Contains(t, keys, TestKeyExampleJson)

	// Delete remaining two key values
	err = rs.Delete(context.Background(), TestKeyExampleKey)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), TestKeyExampleJson)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Empty(t, keys)

	keys, err = rs.List(context.Background(), TestKeyCertPath, true)
	assert.NoError(t, err)
	assert.Empty(t, keys)
}

func TestEtcdStorage_ListNonRecursive(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	// Store three key values
	err := rs.Store(context.Background(), TestKeyExampleCrt, TestValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), TestKeyExampleKey, TestValueKey)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), TestKeyExampleJson, TestValueJson)
	assert.NoError(t, err)

	// List non-recursively from root
	keys, err := rs.List(context.Background(), "", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, TestKeyCertPath)

	// List non-recursively from first level
	keys, err = rs.List(context.Background(), TestKeyCertPath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, TestKeyAcmePath)

	// List non-recursively from second level
	keys, err = rs.List(context.Background(), TestKeyAcmePath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, TestKeyExamplePath)

	// List non-recursively from third level
	keys, err = rs.List(context.Background(), TestKeyExamplePath, false)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, TestKeyExampleCrt)
	assert.Contains(t, keys, TestKeyExampleKey)
	assert.Contains(t, keys, TestKeyExampleJson)
}

func TestEtcdStorage_LockUnlock(t *testing.T) {

	rs := NewCertStore("wag-certificates")

	err := rs.Lock(context.Background(), TestKeyLock)
	assert.NoError(t, err)

	err = rs.Unlock(context.Background(), TestKeyLock)
	assert.NoError(t, err)
}
