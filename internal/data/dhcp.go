package data

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/rs/zerolog/log"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
	"go.etcd.io/etcd/client/v3/concurrency"
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

	txn := tetcd.NewTxn(ctx, d.etcd)
	then, elseTxn := txn.Conditional(clientv3util.KeyExists(InternalConfig.Devices.DHCP.End().Key()))

	endH := tetcd.GetTx(then, InternalConfig.Devices.DHCP.End())

	// As a migration step, if the dhcp end key isnt found, we place it with the ip address next to the servers ip address within the cidr
	tetcd.PutTx(elseTxn, InternalConfig.Devices.DHCP.End(), incrementIP(serverIP, 1).String())

	if err := txn.Commit(); err != nil {
		return nil, fmt.Errorf("failed to get end of ip range: %w", err)
	}

	// set the default as one next to the server
	var addr net.IP = incrementIP(serverIP, 1)
	if txn.Succeeded() {

		strAddr, err := endH.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal end dhcp ip address %s: %w", addr, err)
		}

		addr = net.ParseIP(strAddr)
	}

	return addr, nil
}

func (d *database) countAbandonedKeys(ctx context.Context) (int64, error) {

	count, err := InternalConfig.Devices.DHCP.Abandoned().Count(ctx, d.etcd)
	if err != nil {
		return 0, fmt.Errorf("failed to count abandoned keys: %w", err)
	}

	return count, nil
}

func (d *database) getLeaseFromAbandoned(ctx context.Context) (string, error) {

	for i := 0; i < 3; i++ {

		addr, err := InternalConfig.Devices.DHCP.Abandoned().Keys(ctx, d.etcd, clientv3.WithLimit(1))
		if err != nil {
			return "", fmt.Errorf("could not find dhcp lease by recycling old addresses: %w", err)
		}

		if len(addr) != 1 {
			return "", errors.New("subnet is full and no more abandoned dhcp leases exist")
		}

		if net.ParseIP(addr[0]) == nil {
			return "", fmt.Errorf("failed to parse end dhcp ip address: %w", err)
		}

		abandonedPath := InternalConfig.Devices.DHCP.Abandoned().Key(addr[0])
		deviceAddressRef := InternalConfig.References.Devices.Address().Key(addr[0])

		txn := tetcd.NewTxn(ctx, d.etcd)
		then, _ := txn.Conditional(clientv3util.KeyMissing(deviceAddressRef.Key()))

		tetcd.DeleteTx(then, abandonedPath)
		err = tetcd.PutTx(then, deviceAddressRef, config.DeviceRef{})
		if err != nil {
			return "", fmt.Errorf("failed to create put value: %w", err)
		}

		if err := txn.Commit(); err != nil {
			return "", err
		}

		if !txn.Succeeded() {
			// if there was a deviceRef despite it being marked abandoned
			// delete the abandoned entry and log it
			// then try again

			abandonedPath.Delete(ctx, d.etcd)

			log.Debug().Str("dhcp_lease", abandonedPath.Key()).Msgf("lease was marked as abandoned, but still has a device reference, this may be bug. ")
			continue
		}

		return addr[0], nil
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

		deviceAddressRef := InternalConfig.References.Devices.Address().Key(start.String())

		// update the end pointer if it is still within the cidr
		txn := tetcd.NewTxn(ctx, d.etcd)
		then, _ := txn.Conditional(clientv3util.KeyMissing(deviceAddressRef.Key()))

		err := tetcd.PutTx(then, InternalConfig.Devices.DHCP.End(), newEnd.String())
		if err != nil {
			return "", fmt.Errorf("failed to create put value: %w", err)
		}

		err = tetcd.PutTx(then, deviceAddressRef, config.DeviceRef{})
		if err != nil {
			return "", fmt.Errorf("failed to create put value: %w", err)
		}

		if err := txn.Commit(); err != nil {
			return "", err
		}

		if txn.Succeeded() {
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

	mutex := concurrency.NewMutex(session, InternalConfig.Devices.DHCP.Locks().Key())

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

	// fast path, if the address we get to start incremented by one is outside the cidr then just try and get from the abandoned pool
	if !cidr.Contains(incrementIP(addr, 1)) {
		return d.getLeaseFromAbandoned(ctx)
	}

	// this will call getLeaseFromAbandoned if it cannot find an ip address by incrementing
	return d.getLeaseFromEndPointer(ctx, addr, cidr)

}
