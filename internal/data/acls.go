package data

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/pkg/control"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/exp/maps"
)

func SetAcl(effects string, policy acls.Acl, overwrite bool) error {

	if err := routetypes.ValidateRules(policy.Mfa, policy.Allow, policy.Deny); err != nil {
		return err
	}

	return set(AclsPrefix+effects, true, policy)
}

func GetPolicies() (result []control.PolicyData, err error) {

	resp, err := etcd.Get(context.Background(), AclsPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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
			Effects:      string(bytes.TrimPrefix(r.Key, []byte(AclsPrefix))),
			PublicRoutes: policy.Allow,
			MfaRoutes:    policy.Mfa,
			DenyRoutes:   policy.Deny,
		})
	}

	return
}

func RemoveAcl(effects string) error {
	_, err := etcd.Delete(context.Background(), AclsPrefix+effects)
	return err
}

func insertMap(m map[string]bool, values ...string) {
	for _, v := range values {
		m[v] = true
	}
}

func hostIPWithMask(ip net.IP) string {
	mask := "/32"
	if ip.To4() == nil && ip.To16() != nil {
		mask = "/128"
	}

	return ip.String() + mask
}

func GetEffectiveAcl(username string) acls.Acl {

	var (
		// Do deduplication for multiple acls
		allowSet = map[string]bool{}
		mfaSet   = map[string]bool{}
		denySet  = map[string]bool{}
	)

	insertMap(allowSet, hostIPWithMask(config.Values.Wireguard.ServerAddress))

	txn := etcd.Txn(context.Background())
	txn.Then(clientv3.OpGet(AclsPrefix+"*"), clientv3.OpGet(AclsPrefix+username), clientv3.OpGet(MembershipKey+"-"+username), clientv3.OpGet(dnsKey))
	resp, err := txn.Commit()
	if err != nil {
		log.Println("failed to get policy data for user", username, "err:", err)
		return acls.Acl{
			Allow: []string{hostIPWithMask(config.Values.Wireguard.ServerAddress)},
		}
	}

	addAcls := func(acl acls.Acl) {
		insertMap(allowSet, acl.Allow...)
		insertMap(mfaSet, acl.Mfa...)
		insertMap(denySet, acl.Deny...)
	}

	// the default policy contents
	if resp.Responses[0].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[0].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			addAcls(acl)
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
			addAcls(acl)
		} else {
			log.Println("failed to unmarshal user specific acls: ", err)
		}
	}

	// Membership map for finding all the other policies
	if resp.Responses[2].GetResponseRange().GetCount() != 0 {
		var userGroups []string

		err = json.Unmarshal(resp.Responses[2].GetResponseRange().Kvs[0].Value, &userGroups)
		if err == nil {
			txn := etcd.Txn(context.Background())

			//If the user belongs to a series of groups, grab those, and add their rules
			var ops []clientv3.Op
			for _, group := range userGroups {
				ops = append(ops, clientv3.OpGet(AclsPrefix+group))
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
					addAcls(acl)
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
				insertMap(allowSet, fmt.Sprintf("%s 53/any", server))
			}
		} else {
			log.Println("failed to unmarshal dns setting: ", err)
		}
	}

	resultingACLs := acls.Acl{
		Allow: maps.Keys(allowSet),
		Mfa:   maps.Keys(mfaSet),
		Deny:  maps.Keys(denySet),
	}

	sort.Strings(resultingACLs.Allow)
	sort.Strings(resultingACLs.Mfa)
	sort.Strings(resultingACLs.Deny)

	return resultingACLs
}
