package data

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func (d *database) GetRegistrationToken(token string) (username, overwrites, staticIP string, group []string, tag string, err error) {

	path := InternalConfig.RegistrationTokens().Key(token)

	var result control.RegistrationResult

	resp, err := concurrency.NewSTM(d.etcd, func(s concurrency.STM) error {

		startingValue := s.Get(path.Key())
		if startingValue == "" {
			return fmt.Errorf("no token")
		}

		token, err := path.Codec().Decode([]byte(startingValue))
		if err != nil {
			return err
		}

		token.NumUses--

		if token.NumUses > 0 {

			value, err := path.Codec().Encode(token)
			if err != nil {
				return err
			}

			s.Put(path.Key(), string(value))
		} else {
			s.Del(path.Key())
		}

		// this feels horribly wrong
		result = token

		return nil
	})

	if err != nil {
		err = fmt.Errorf("failed to get registration token: %w", err)
		return
	}

	if !resp.Succeeded {
		err = fmt.Errorf("failed to transact on registration token")
		return
	}

	return result.Username, result.Overwrites, result.StaticIP, result.Groups, result.Tag, nil
}

// Returns list of tokens
func (d *database) GetRegistrationTokens() (results []control.RegistrationResult, err error) {

	order, tokens, err := InternalConfig.RegistrationTokens().List(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, token := range order {
		results = append(results, tokens[token])
	}

	return results, nil
}

func (d *database) DeleteRegistrationToken(identifier string) error {
	_, err := InternalConfig.RegistrationTokens().Key(identifier).Delete(context.Background(), d.etcd)
	return err
}

// Randomly generate a token for a specific username
func (d *database) GenerateRegistrationToken(username, overwrite, staticIp string, groups []string, uses int, tag string) (token string, err error) {
	token, err = utils.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}

	err = d.AddRegistrationToken(token, username, overwrite, staticIp, groups, uses, tag)
	return
}

// Add a token to the database to add or overwrite a device for a user, may fail of the token does not meet complexity requirements
func (d *database) AddRegistrationToken(token, username, overwrite, staticIp string, groups []string, uses int, tag string) error {
	if len(token) < 32 {
		return errors.New("registration token is too short")
	}

	if len(token) > 128 {
		return errors.New("registration token too long")
	}

	if !allowedTokenCharacters.Match([]byte(token)) {
		return errors.New("registration token contains illegal characters (allowed characters a-z A-Z - . _ )")
	}

	if strings.Contains(username, "-") {
		return errors.New("usernames cannot contain '-' ")
	}

	if username == "" {
		return errors.New("usernames cannot be empty")
	}

	if _, err := netip.ParseAddr(staticIp); err != nil && staticIp != "" {
		return fmt.Errorf("static ip was not parsable as an ip address: %w", err)
	}

	if len(tag) > 100 {
		return fmt.Errorf("tag was too large >100")
	}

	if overwrite != "" {

		deviceRef, err := InternalConfig.References.Devices.Address().Key(overwrite).Get(context.Background(), d.etcd)
		if err != nil {
			return err
		}

		if deviceRef.Empty() {
			return errors.New("no device with that ip")
		}

		device, err := InternalConfig.Devices.Machines().
			Key(username).
			Key(deviceRef.Address).
			Get(context.Background(), d.etcd)
		if err != nil {
			return fmt.Errorf("could not find device that this token is intended to overwrite: %w", err)
		}

		if device.Username != username {
			return fmt.Errorf("device cannot be overwritten to different user: %w", err)
		}
	}

	if len(groups) > 0 {

		checks := []clientv3.Cmp{}
		for _, group := range groups {
			checks = append(checks, clientv3util.KeyExists(InternalConfig.Indexes.Groups().Key(group).Key()))
		}

		txn := d.etcd.Txn(context.Background())
		txn.If(checks...)

		resp, err := txn.Commit()
		if err != nil {
			return fmt.Errorf("failed to check that groups exist: %w", err)
		}

		if !resp.Succeeded {
			return fmt.Errorf("groups %v do not all exist", groups)
		}
	}

	result := control.RegistrationResult{
		Token:      token,
		Username:   username,
		Overwrites: overwrite,
		StaticIP:   staticIp,
		Groups:     groups,
		NumUses:    uses,
		Tag:        tag,
	}

	newRegistrationToken := InternalConfig.RegistrationTokens().Key(token)

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, _ := txn.Conditional(clientv3util.KeyMissing(newRegistrationToken.Key()))
	tetcd.PutTx(then, newRegistrationToken, result)

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to add registration token: %w", err)
	}

	if !txn.Succeeded() {
		return fmt.Errorf("%q already exists", token)
	}

	return nil

}
