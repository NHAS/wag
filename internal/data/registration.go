package data

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func restrationKey(token string) string {
	return fmt.Sprintf("tokens-%s", token)
}

func GetRegistrationToken(token string) (username, overwrites string, group []string, err error) {

	minTime := time.After(1 * time.Second)

	response, err := etcd.Get(context.Background(), restrationKey(token))
	if err != nil {
		return
	}

	if len(response.Kvs) != 1 {
		err = errors.New("invalid token")
		return
	}

	var result control.RegistrationResult
	err = json.Unmarshal(response.Kvs[0].Value, &result)

	<-minTime

	if err != nil {
		return
	}

	return result.Username, result.Overwrites, result.Groups, nil
}

// Returns list of tokens
func GetRegistrationTokens() (results []control.RegistrationResult, err error) {

	response, err := etcd.Get(context.Background(), "tokens-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var result control.RegistrationResult
		err := json.Unmarshal(res.Value, &result)
		if err != nil {
			return nil, err
		}

		results = append(results, result)
	}

	return results, nil
}

func DeleteRegistrationToken(identifier string) error {
	_, err := etcd.Delete(context.Background(), restrationKey(identifier))
	if err != nil {
		return err
	}

	return err
}

// FinaliseRegistration may or may not delete the token in question depending on whether the number of uses is <= 0
func FinaliseRegistration(token string) error {

	errVal := errors.New("registration token has expired")
	err := doSafeUpdate(context.Background(), "tokens-"+token, func(gr *clientv3.GetResponse) (string, bool, error) {

		var result control.RegistrationResult
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", false, err
		}

		result.NumUses--

		if result.NumUses <= 0 {
			err = errVal
		}

		b, _ := json.Marshal(result)

		return string(b), false, err
	})

	if err == errVal {
		return DeleteRegistrationToken(token)
	}

	return nil
}

// Randomly generate a token for a specific username
func GenerateToken(username, overwrite string, groups []string, uses int) (token string, err error) {
	tokenBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}

	token = hex.EncodeToString(tokenBytes)
	err = AddRegistrationToken(token, username, overwrite, groups, uses)

	return
}

// Add a token to the database to add or overwrite a device for a user, may fail of the token does not meet complexity requirements
func AddRegistrationToken(token, username, overwrite string, groups []string, uses int) error {
	if len(token) < 32 {
		return errors.New("registration token is too short")
	}

	if !allowedTokenCharacters.Match([]byte(token)) {
		return errors.New("registration token contains illegal characters (allowed characters a-z A-Z - . _ )")
	}

	var err error
	if overwrite != "" {

		response, err := etcd.Get(context.Background(), "device-ref-"+overwrite)
		if err != nil {
			return err
		}

		if !bytes.Contains(response.Kvs[0].Value, []byte(username)) {
			return errors.New("could not find device that this token is intended to overwrite")
		}
	}

	result := control.RegistrationResult{
		Token:      token,
		Username:   username,
		Overwrites: overwrite,
		Groups:     groups,
		NumUses:    uses,
	}

	b, _ := json.Marshal(result)

	_, err = etcd.Put(context.Background(), "tokens-"+token, string(b))

	return err
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
