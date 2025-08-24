package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

func (d *database) registrationKey(token string) string {
	return fmt.Sprintf("tokens-%s", token)
}

func (d *database) GetRegistrationToken(token string) (username, overwrites, staticIP string, group []string, tag string, err error) {

	minTime := time.After(1 * time.Second)

	result, err := Get[control.RegistrationResult](d.etcd, d.registrationKey(token))

	<-minTime

	if err != nil {
		return
	}

	return result.Username, result.Overwrites, result.StaticIP, result.Groups, result.Tag, nil
}

// Returns list of tokens
func (d *database) GetRegistrationTokens() (results []control.RegistrationResult, err error) {

	response, err := d.etcd.Get(context.Background(), tokensKey, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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

func (d *database) DeleteRegistrationToken(identifier string) error {
	_, err := d.etcd.Delete(context.Background(), d.registrationKey(identifier))
	return err
}

// FinaliseRegistration may or may not delete the token in question depending on whether the number of uses is <= 0
func (d *database) FinaliseRegistration(token string) error {

	errVal := errors.New("registration token has expired")

	err := d.doSafeUpdate(context.Background(), tokensKey+token, false, func(gr *clientv3.GetResponse) (string, error) {

		var result control.RegistrationResult
		err := json.Unmarshal(gr.Kvs[0].Value, &result)
		if err != nil {
			return "", err
		}

		result.NumUses--

		if result.NumUses <= 0 {
			err = errVal
		}

		b, _ := json.Marshal(result)

		return string(b), err
	})

	if err == errVal {
		return d.DeleteRegistrationToken(token)
	}

	if err != nil {
		return err
	}

	return nil
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

		response, err := d.etcd.Get(context.Background(), deviceRef+overwrite)
		if err != nil {
			return err
		}

		if len(response.Kvs) < 1 {
			return errors.New("no device with that ip")
		}

		device, err := Get[Device](d.etcd, deviceRef+overwrite)
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
			checks = append(checks, clientv3util.KeyExists(GroupsPrefix+group))
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

	return Set(d.etcd, tokensKey+token, false, result)

}
