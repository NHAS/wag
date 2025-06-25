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

func (d *database) SetAcl(effects string, policy acls.Acl, overwrite bool) error {

	if err := routetypes.ValidateRules(policy.Mfa, policy.Allow, policy.Deny); err != nil {
		return err
	}

	return Set(d.etcd, AclsPrefix+effects, true, policy)
}

func (d *database) GetPolicies() (result []control.PolicyData, err error) {

	resp, err := d.etcd.Get(context.Background(), AclsPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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

func (d *database) RemoveAcl(effects string) error {
	_, err := d.etcd.Delete(context.Background(), AclsPrefix+effects)
	return err
}

func (d *database) insertMap(m map[string]bool, values ...string) {
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

func (d *database) GetEffectiveAcl(username string) acls.Acl {

	var (
		// Do deduplication for multiple acls
		allowSet = map[string]bool{}
		mfaSet   = map[string]bool{}
		denySet  = map[string]bool{}
	)

	d.insertMap(allowSet, hostIPWithMask(config.Values.Wireguard.ServerAddress))

	userMembershipKey := fmt.Sprintf("%s%s-", GroupMembershipPrefix, username)

	txn := d.etcd.Txn(context.Background())
	txn.Then(
		clientv3.OpGet(AclsPrefix+"*"),
		clientv3.OpGet(AclsPrefix+username),
		clientv3.OpGet(userMembershipKey, clientv3.WithKeysOnly(), clientv3.WithPrefix()),
		clientv3.OpGet(dnsKey),
	)
	resp, err := txn.Commit()
	if err != nil {
		log.Println("failed to get policy data for user", username, "err:", err)
		return acls.Acl{
			Allow: []string{hostIPWithMask(config.Values.Wireguard.ServerAddress)},
		}
	}

	addAcls := func(acl acls.Acl) {
		d.insertMap(allowSet, acl.Allow...)
		d.insertMap(mfaSet, acl.Mfa...)
		d.insertMap(denySet, acl.Deny...)
	}

	// the default policy contents
	if resp.Responses[0].GetResponseRange().GetCount() != 0 {
		var acl acls.Acl

		err := json.Unmarshal(resp.Responses[0].GetResponseRange().Kvs[0].Value, &acl)
		if err == nil {
			addAcls(acl)
		} else {
			d.RaiseError(err, []byte("failed to unmarshal default acls policy"))
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
	if membership := resp.Responses[2].GetResponseRange(); membership.GetCount() != 0 {

		var ops []clientv3.Op
		for _, kv := range membership.Kvs {

			// strips [wag-membership-username-]groupnames
			resultParts, err := d.SplitKey(1, userMembershipKey, string(kv.Key))
			if err != nil {
				log.Println("failed to get group membership: ", err)
				continue
			}

			group := resultParts[0]
			ops = append(ops, clientv3.OpGet(AclsPrefix+group))
		}

		txn := d.etcd.Txn(context.Background())
		resp, err := txn.Then(ops...).Commit()
		if err != nil {
			log.Println("failed to fetch acls from db groups: ", err)
			d.RaiseError(err, []byte("failed to fetch acls from db groups"))
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

	}

	// Add dns servers if defined
	// Restrict dns servers to only having 53/any by default as per #49
	if resp.Responses[3].GetResponseRange().GetCount() != 0 {

		var dns []string
		err = json.Unmarshal(resp.Responses[3].GetResponseRange().Kvs[0].Value, &dns)
		if err == nil {
			for _, server := range dns {
				d.insertMap(allowSet, fmt.Sprintf("%s 53/any", server))
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
