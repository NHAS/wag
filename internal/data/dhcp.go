package data

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	dhcpPrefix          = "wag/dhcp"
	dhcpAbandonedPrefix = dhcpPrefix + "/abandoned/"
)

func incrementIP(ip net.IP, inc uint) net.IP {

	if ip.To4() != nil {
		r := binary.BigEndian.Uint32(ip.To4()) + uint32(inc)

		newIp := make([]byte, 4)
		binary.BigEndian.PutUint32(newIp, r)

		return net.IP(newIp)
	}

	ip = ip.To16()

	asBigInt := big.NewInt(0).SetBytes(ip)
	asBigInt.Add(asBigInt, big.NewInt(int64(inc)))

	result := make([]byte, 16)
	bigIntBytes := asBigInt.Bytes()

	copy(result[16-min(len(bigIntBytes), 16):], bigIntBytes)

	return net.IP(result)

}

// https://github.com/IBM/netaddr/blob/master/net_utils.go#L73
func broadcastAddr(n *net.IPNet) net.IP {
	// The golang net package doesn't make it easy to calculate the broadcast address. :(
	var broadcast net.IP
	switch len(n.IP) {
	case 4:
		broadcast = net.ParseIP("0.0.0.0").To4()
	case 16:
		broadcast = net.ParseIP("::")
	default:
		panic("Bad value for size")
	}

	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

func (d *database) determineIPStartPoint(ctx context.Context, serverIP net.IP) (net.IP, error) {

	txn := d.etcd.Txn(ctx)

	// As a migration step, if the dhcp end key isnt found, we place it with the ip address next to the servers ip address within the cidr
	txn.If(
		clientv3util.KeyExists(dhcpPrefix + "/end"),
	).Then(
		clientv3.OpGet(dhcpPrefix + "/end"),
	).Else(
		clientv3.OpPut(dhcpPrefix+"/end", fmt.Sprintf("%q", incrementIP(serverIP, 1))),
	)

	resp, err := txn.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to get end of ip range: %w", err)
	}

	// set the default as one next to the server
	var addr net.IP = incrementIP(serverIP, 1)
	if resp.Succeeded {

		err = json.Unmarshal(resp.Responses[0].GetResponseRange().Kvs[0].Value, &addr)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal end dhcp ip address %s: %w", string(resp.Responses[0].GetResponseRange().Kvs[0].Value), err)
		}

	}

	return addr, nil
}

func (d *database) countAbandonedKeys(ctx context.Context) (int64, error) {
	resp, err := d.etcd.Get(ctx, dhcpAbandonedPrefix, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		return 0, fmt.Errorf("failed to count abandoned keys: %w", err)
	}

	return resp.Count, nil
}

func (d *database) getLeaseFromAbandoned(ctx context.Context) (string, error) {
	var addr net.IP

	for i := 0; i < 3; i++ {
		resp, err := d.etcd.Get(ctx, dhcpAbandonedPrefix, clientv3.WithPrefix(), clientv3.WithLimit(1))
		if err != nil {
			return "", fmt.Errorf("could not find dhcp lease by recycling old addresses: %w", err)
		}

		if len(resp.Kvs) != 1 {
			return "", errors.New("subnet is full and no more abandoned dhcp leases exist")
		}

		err = json.Unmarshal(resp.Kvs[0].Value, &addr)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal end dhcp ip address: %w", err)
		}

		txn := d.etcd.Txn(ctx)
		txn.If(
			clientv3util.KeyMissing(deviceRef+addr.String()),
		).Then(
			clientv3.OpPut(deviceRef+addr.String(), ""),
			clientv3.OpDelete(string(resp.Kvs[0].Key)),
		)

		txnResp, err := txn.Commit()
		if err != nil {
			return "", err
		}

		if !txnResp.Succeeded {
			// if there was a deviceRef despite it being marked abandoned
			// delete the abandoned entry and log it
			// then try again

			d.etcd.Delete(ctx, string(resp.Kvs[0].Key))

			log.Printf("%q was marked as abandoned, but still has a device reference, this may be bug. ", string(resp.Kvs[0].Key))
			continue
		}

		return addr.String(), nil
	}

	return "", fmt.Errorf("failed to get dhcp lease in allotted time, your subnet maybe full")
}

func (d *database) getLeaseFromEndPointer(ctx context.Context, start net.IP, cidr *net.IPNet) (string, error) {
	one, bits := cidr.Mask.Size()
	sizeOfNetwork := int(math.Pow(2, float64(bits-one)))

	// this just puts an upper bound on how many times this will increment.
	// In actual fact this should never increment
	for i := 0; i <= sizeOfNetwork/2; i++ {

		select {
		case <-ctx.Done():
			return "", errors.New("context finished, dhcp allocation operation timed out")
		default:
		}

		newEnd := incrementIP(start, 1)
		if !cidr.Contains(incrementIP(start, 1)) {
			newEnd = start
		}

		// update the end pointer if it is still within the cidr
		txn := d.etcd.Txn(ctx)
		txn.If(
			clientv3util.KeyMissing(deviceRef+start.String()),
		).Then(
			clientv3.OpPut(deviceRef+start.String(), ""),
			clientv3.OpPut(dhcpPrefix+"/end", fmt.Sprintf("%q", newEnd)),
		)

		resp, err := txn.Commit()
		if err != nil {
			return "", err
		}

		if resp.Succeeded {
			return start.String(), nil
		}

		start = incrementIP(start, 1)

		if cidr.Contains(start) && !broadcastAddr(cidr).Equal(start) {
			continue
		}

		// if we've moved out of the cidr, then last ditch try getting them from the abandoned pool
		return d.getLeaseFromAbandoned(ctx)
	}

	return "", fmt.Errorf("could not find a dhcp lease")
}

func (d *database) getNextIP(subnet string) (string, error) {

	serverIP, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	cidr.Mask.Size()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := concurrency.NewSession(d.etcd, concurrency.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("failed to create lock session: %w", err)
	}
	defer session.Close()

	mutex := concurrency.NewMutex(session, dhcpPrefix+"/locks")

	err = mutex.Lock(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to acquire dhcp lock: %w", err)
	}

	count, err := d.countAbandonedKeys(ctx)
	if err != nil {
		return "", err
	}

	if count > 0 {
		return d.getLeaseFromAbandoned(ctx)
	}

	addr, err := d.determineIPStartPoint(ctx, serverIP)
	if err != nil {
		return "", err
	}

	log.Println("starting point: ", addr)

	// fast path, if the address we get to start incremented by one is outside the cidr then just try and get from the abandoned pool
	if !cidr.Contains(incrementIP(addr, 1)) {
		return d.getLeaseFromAbandoned(ctx)
	}

	// this will call getLeaseFromAbandoned if it cannot find an ip address by incrementing
	return d.getLeaseFromEndPointer(ctx, addr, cidr)

}
