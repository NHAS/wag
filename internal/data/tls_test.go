package data

// Adapted from https://github.com/pberkel/caddy-storage-Etcd/blob/main/storage_test.go

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"testing"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	"github.com/stretchr/testify/assert"
)

var (
	testValueCrt  = []byte("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu")
	testValueKey  = []byte("RWdlc3RhcyBlZ2VzdGFzIGZyaW5naWxsYSBwaGFzZWxsdXMgZmF1Y2lidXMgc2NlbGVyaXNxdWUgZWxlaWZlbmQgZG9uZWMgcHJldGl1bSB2dWxwdXRhdGUuIFRpbmNpZHVudCBvcm5hcmUgbWFzc2EgZWdldC4=")
	testValueJson = []byte("U2FnaXR0aXMgYWxpcXVhbSBtYWxlc3VhZGEgYmliZW5kdW0gYXJjdSB2aXRhZSBlbGVtZW50dW0uIEludGVnZXIgbWFsZXN1YWRhIG51bmMgdmVsIHJpc3VzIGNvbW1vZG8gdml2ZXJyYSBtYWVjZW5hcy4=")
	rs            *CertMagicStore
)

func TestMain(m *testing.M) {

	if err := config.Load("../config/testing_config3.json"); err != nil {
		log.Println("failed to load config: ", err)
		os.Exit(1)
	}

	db, err := Load("", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	rs = NewCertStore(db.etcd, "wag-certificates")

	os.Exit(m.Run())
}

func generateRandomPath(t *testing.T) string {

	dummyFile, err := utils.GenerateRandomHex(32)
	assert.NoError(t, err)

	return dummyFile
}

func TestEtcdStorage_Store(t *testing.T) {

	err := rs.Store(context.Background(), generateRandomPath(t), testValueCrt)
	assert.NoError(t, err)
}

func TestEtcdStorage_Exists(t *testing.T) {

	path := generateRandomPath(t)

	exists := rs.Exists(context.Background(), path)
	assert.False(t, exists)

	err := rs.Store(context.Background(), path, testValueCrt)
	assert.NoError(t, err)

	exists = rs.Exists(context.Background(), path)
	assert.True(t, exists)
}

func TestEtcdStorage_Load(t *testing.T) {

	path := generateRandomPath(t)

	err := rs.Store(context.Background(), path, testValueCrt)
	assert.NoError(t, err)

	loadedValue, err := rs.Load(context.Background(), path)
	assert.NoError(t, err)

	assert.Equal(t, testValueCrt, loadedValue)
}

func TestEtcdStorage_Delete(t *testing.T) {

	path := generateRandomPath(t)

	err := rs.Store(context.Background(), path, testValueCrt)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), path)
	assert.NoError(t, err)

	exists := rs.Exists(context.Background(), path)
	assert.False(t, exists)

	loadedValue, err := rs.Load(context.Background(), path)
	assert.Nil(t, loadedValue)

	notExist := errors.Is(err, fs.ErrNotExist)
	assert.True(t, notExist)
}

func TestEtcdStorage_Stat(t *testing.T) {

	path := generateRandomPath(t)

	size := int64(len(testValueCrt))

	err := rs.Store(context.Background(), path, testValueCrt)
	assert.NoError(t, err)

	stat, err := rs.Stat(context.Background(), path)
	assert.NoError(t, err)

	assert.Equal(t, path, stat.Key)
	assert.Equal(t, size, stat.Size)
}

func TestEtcdStorage_Exists_Handles_Directories(t *testing.T) {
	testKey, err := utils.GenerateRandomHex(32)
	assert.NoError(t, err)

	certPath := testKey + generateRandomPath(t)

	err = rs.Store(context.Background(), certPath, []byte("floop"))
	assert.NoError(t, err)

	r := rs.Exists(context.Background(), certPath)
	assert.True(t, r, certPath)

	r = rs.Exists(context.Background(), testKey)
	assert.True(t, r, certPath)

}

func TestEtcdStorage_List(t *testing.T) {

	err := rs.Delete(context.Background(), "")
	assert.NoError(t, err)

	testKey := "test/"

	certPath := testKey + generateRandomPath(t)
	keyPath := testKey + generateRandomPath(t)

	dummyPath := testKey + generateRandomPath(t)

	randomPath := generateRandomPath(t)

	// Store two key values
	err = rs.Store(context.Background(), keyPath, testValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), certPath, testValueKey)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), randomPath, testValueKey)
	assert.NoError(t, err)

	// List recursively from root
	keys, err := rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, keyPath)
	assert.Contains(t, keys, randomPath)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), testKey, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, keyPath)

	// Store third key value
	err = rs.Store(context.Background(), dummyPath, testValueJson)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 4)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, keyPath)
	assert.Contains(t, keys, dummyPath)
	assert.Contains(t, keys, randomPath)

	// List recursively from first directory
	keys, err = rs.List(context.Background(), testKey, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, keyPath)
	assert.Contains(t, keys, dummyPath)

	// Delete one key value
	err = rs.Delete(context.Background(), keyPath)
	assert.NoError(t, err)

	// List recursively from root
	keys, err = rs.List(context.Background(), "", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.NotContains(t, keys, keyPath)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, dummyPath)
	assert.Contains(t, keys, randomPath)

	keys, err = rs.List(context.Background(), testKey, true)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, keyPath)
	assert.Contains(t, keys, certPath)
	assert.Contains(t, keys, dummyPath)

	// Delete remaining two key values
	err = rs.Delete(context.Background(), dummyPath)
	assert.NoError(t, err)

	err = rs.Delete(context.Background(), certPath)
	assert.NoError(t, err)
}

func TestEtcdStorage_ListNonRecursive(t *testing.T) {
	err := rs.Delete(context.Background(), "")
	assert.NoError(t, err)

	path1 := generateRandomPath(t)
	path2 := generateRandomPath(t)
	path3 := generateRandomPath(t)

	// Store three key values
	err = rs.Store(context.Background(), "file0", testValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), path1+"/file1", testValueCrt)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), path1+"/"+path2+"/file2", testValueKey)
	assert.NoError(t, err)

	err = rs.Store(context.Background(), path1+"/"+path2+"/"+path3+"/file3", testValueJson)
	assert.NoError(t, err)

	// List non-recursively from root
	keys, err := rs.List(context.Background(), "", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "file0")
	assert.Contains(t, keys, path1)

	// List non-recursively from first level
	keys, err = rs.List(context.Background(), path1+"/", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, path1+"/file1")
	assert.Contains(t, keys, path1+"/"+path2)

	// List non-recursively from second level
	keys, err = rs.List(context.Background(), path1+"/"+path2+"/", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, path1+"/"+path2+"/file2")
	assert.Contains(t, keys, path1+"/"+path2+"/"+path3)

	// List non-recursively from third level
	keys, err = rs.List(context.Background(), path1+"/"+path2+"/"+path3+"/", false)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, path1+"/"+path2+"/"+path3+"/file3")

}

func TestEtcdStorage_LockUnlock(t *testing.T) {

	testKeyLock := generateRandomPath(t)

	err := rs.Lock(context.Background(), testKeyLock)
	assert.NoError(t, err)

	err = rs.Unlock(context.Background(), testKeyLock)
	assert.NoError(t, err)
}
