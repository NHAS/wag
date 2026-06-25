package data

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd"
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

	return Config.Acls.Policies().Key(effects).Put(context.Background(), d.etcd, &policy)
}

func (d *database) GetPolicies() (policies []control.PolicyData, err error) {

	result, err := Config.Acls.Policies().List(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, r := range result.Order {

		policies = append(policies, control.PolicyData{
			Effects:      r,
			PublicRoutes: result.Values[r].Allow,
			MfaRoutes:    result.Values[r].Mfa,
			DenyRoutes:   result.Values[r].Deny,
		})
	}

	return
}

func (d *database) RemoveAcl(effects string) error {
	_, err := Config.Acls.Policies().Key(effects).Delete(context.Background(), d.etcd)
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

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	globalPolicy := tetcd.GetTx(then, Config.Acls.Policies().Key("*"))
	userPolicies := tetcd.GetTx(then, Config.Acls.Policies().Key(username))
	dnsServers := tetcd.GetTx(then, Config.Wireguard.DNS())
	usersGroups := tetcd.ListTx(then, InternalConfig.Indexes.UserMembership().Key(username), clientv3.WithKeysOnly())

	if err := txn.Commit(); err != nil {

		log.Error().Err(err).Str("username", username).Msg("failed to get policy data for user")

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
	acl, err := globalPolicy.Value()
	if err == nil {
		addAcls(*acl)
	} else {
		d.RaiseError(err, []byte("failed to unmarshal default acls policy"))
		log.Error().Err(err).Str("username", username).Msg("failed to unmarshal default acls policy")
	}

	// Add dns servers if defined
	// Restrict dns servers to only having 53/any by default as per #49

	dns, err := dnsServers.Value()
	if err == nil {
		for _, server := range dns {
			// we dont allow hostnames to get added to the allowed entries here
			// this mirrors how the DNS entry in the wg config works
			_, err := netip.ParseAddr(server)
			if err != nil {
				continue
			}

			d.insertMap(allowSet, fmt.Sprintf("%s 53/any", server))
		}
	} else {
		log.Error().Err(err).Str("username", username).Msg("failed to unmarshal dns setting")
	}

	// User specific acls
	acl, err = userPolicies.Value()
	if err == nil {
		addAcls(*acl)
	} else {
		log.Error().Err(err).Str("username", username).Msg("failed to unmarshal user specific acls")
		d.RaiseError(err, []byte(fmt.Sprintf("failed to decode %q acls check policies", username)))
	}

	groups, err := usersGroups.Keys()
	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("failed to fetch acls from db groups")
		d.RaiseError(err, []byte("failed to fetch acls from db groups"))
	}

	// Membership map for finding all the other policies
	membersTxn := tetcd.NewTxn(context.Background(), d.etcd)

	then = membersTxn.Then()
	membershipAcls := make([]*tetcd.GetHandle[*acls.Acl], 0, len(groups))
	for _, group := range groups {
		membershipAcls = append(membershipAcls, tetcd.GetTx(then, Config.Acls.Policies().Key(group)))
	}

	err = membersTxn.Commit()
	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("failed to fetch acls from db groups")

		d.RaiseError(err, []byte("failed to fetch acls from db groups"))
	} else {
		var errs []error
		for i := range membershipAcls {
			acl, err := membershipAcls[i].Value()
			if err != nil {
				errs = append(errs, err)
				continue
			}

			addAcls(*acl)
		}

		if err := errors.Join(errs...); err != nil {
			log.Error().Err(err).Str("username", username).Msg("failed to unmarshal group specific acls")
			d.RaiseError(err, []byte("failed to unmarshal group specific acls"))
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
