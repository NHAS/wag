package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/config"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func SetAcl(effects string, policy acls.Acl, overwrite bool) error {

	response, err := etcd.Get(context.Background(), "wag-acls-"+effects)
	if err != nil {
		return err
	}

	if len(response.Kvs) > 0 && !overwrite {
		return errors.New("acl already exists")
	}

	policyJson, _ := json.Marshal(policy)

	_, err = etcd.Put(context.Background(), "wag-acls-"+effects, string(policyJson))

	return err
}

func RemoveAcl(effects string) error {
	_, err := etcd.Delete(context.Background(), "wag-acls-"+effects)
	return err
}

func GetEffectiveAcl(username string) acls.Acl {
	var resultingACLs acls.Acl
	//Add the server address by default
	resultingACLs.Allow = []string{config.Values().Wireguard.ServerAddress.String() + "/32"}

	// Add dns servers if defined
	// Make sure we resolve the dns servers in case someone added them as domains, so that clients dont get stuck trying to use the domain dns servers to look up the dns servers
	// Restrict dns servers to only having 53/any by default as per #49
	for _, server := range config.Values().Wireguard.DNS {
		resultingACLs.Allow = append(resultingACLs.Allow, fmt.Sprintf("%s 53/any", server))
	}

	txn := etcd.Txn(context.Background())
	txn.Then(clientv3.OpGet("wag-acls-*"), clientv3.OpGet("wag-acls-"+username), clientv3.OpGet("wag-membership"))
	resp, err := txn.Commit()
	if err != nil {
		return acls.Acl{}
	}

	// the default policy contents
	if resp.Responses[0].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[0].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
			resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
		}
	}

	// User specific acls
	if resp.Responses[1].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[1].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
			resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
		}
	}

	// Membership map for finding all the other policies
	if resp.Responses[2].GetResponseRange().GetCount() != 0 {
		var rGroupLookup map[string]map[string]bool

		err = json.Unmarshal(resp.Responses[2].GetResponseRange().Kvs[0].Value, &rGroupLookup)
		if err == nil {

			txn := etcd.Txn(context.Background())

			//If the user belongs to a series of groups, grab those, and add their rules
			var ops []clientv3.Op
			for group := range rGroupLookup[username] {
				ops = append(ops, clientv3.OpGet("wag-acls-"+group))
			}

			resp, err := txn.Then(ops...).Commit()
			if err != nil {
				return acls.Acl{}
			}

			for m := range resp.Responses {
				r := resp.Responses[m].GetResponseRange()
				if r.Count > 0 {

					var acl acls.Acl

					err := json.Unmarshal(r.Kvs[0].Value, &acl)
					if err != nil {
						continue
					}

					resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
					resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
				}
			}

		}
	}

	return resultingACLs
}
