package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

func SetAcl(effects string, policy acls.Acl, overwrite bool) error {

	if err := routetypes.ValidateRules(policy.Mfa, policy.Allow, policy.Deny); err != nil {
		return err
	}

	policyJson, _ := json.Marshal(policy)

	if overwrite {
		_, err := etcd.Put(context.Background(), "wag-acls-"+effects, string(policyJson))
		return err
	}

	txn := etcd.Txn(context.Background())
	txn.If(clientv3util.KeyMissing("wag-acls-" + effects))
	txn.Then(clientv3.OpPut("wag-acls-"+effects, string(policyJson)))

	resp, err := txn.Commit()
	if err != nil {
		return err
	}

	if !resp.Succeeded {
		return errors.New("acl already exists")
	}

	return err
}

func GetPolicies() (result []control.PolicyData, err error) {

	resp, err := etcd.Get(context.Background(), "wag-acls-", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, r := range resp.Kvs {

		var policy acls.Acl
		err := json.Unmarshal(r.Value, &policy)
		if err != nil {
			return nil, err
		}

		result = append(result, control.PolicyData{
			Effects:      string(bytes.TrimPrefix(r.Key, []byte("wag-acls-"))),
			PublicRoutes: policy.Allow,
			MfaRoutes:    policy.Mfa,
			DenyRoutes:   policy.Deny,
		})
	}

	return
}

func RemoveAcl(effects string) error {
	_, err := etcd.Delete(context.Background(), "wag-acls-"+effects)
	return err
}

func GetEffectiveAcl(username string) acls.Acl {
	var resultingACLs acls.Acl
	//Add the server address by default
	resultingACLs.Allow = []string{config.Values.Wireguard.ServerAddress.String() + "/32"}

	txn := etcd.Txn(context.Background())
	txn.Then(clientv3.OpGet("wag-acls-*"), clientv3.OpGet("wag-acls-"+username), clientv3.OpGet(MembershipKey), clientv3.OpGet(dnsKey))
	resp, err := txn.Commit()
	if err != nil {
		log.Println("failed to get policy data for user", username, "err:", err)
		return acls.Acl{}
	}

	// the default policy contents
	if resp.Responses[0].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[0].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
			resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
		} else {
			RaiseError(err, []byte("failed to unmarshal default acls policy"))
			log.Println("failed to unmarshal default acls policy: ", err)
		}
	}

	// User specific acls
	if resp.Responses[1].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[1].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
			resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
		} else {
			log.Println("failed to unmarshal user specific acls: ", err)
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
				log.Println("failed to get acls for groups: ", err)
				RaiseError(err, []byte("failed to determine acls from groups"))
				return acls.Acl{}
			}

			for m := range resp.Responses {
				r := resp.Responses[m].GetResponseRange()
				if r.Count > 0 {

					var acl acls.Acl

					err := json.Unmarshal(r.Kvs[0].Value, &acl)
					if err != nil {
						log.Println("failed to unmarshal acl from response: ", err, string(r.Kvs[0].Value))
						continue
					}

					resultingACLs.Allow = append(resultingACLs.Allow, acl.Allow...)
					resultingACLs.Mfa = append(resultingACLs.Mfa, acl.Mfa...)
				}
			}

		} else {
			log.Println("failed to decode reverse group mapping: ", err)
		}
	}

	// Add dns servers if defined
	// Restrict dns servers to only having 53/any by default as per #49
	if resp.Responses[3].GetResponseRange().GetCount() != 0 {

		var dns []string
		err = json.Unmarshal(resp.Responses[3].GetResponseRange().Kvs[0].Value, &dns)
		if err == nil {
			for _, server := range dns {
				resultingACLs.Allow = append(resultingACLs.Allow, fmt.Sprintf("%s 53/any", server))
			}
		} else {
			log.Println("failed to unmarshal dns setting: ", err)
		}
	}

	return resultingACLs
}
