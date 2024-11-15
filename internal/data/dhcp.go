package data

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"net"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
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

func chooseInitalIP(cidr *net.IPNet) (net.IP, error) {

	max := 128
	if cidr.IP.To4() != nil {
		max = 32
	}

	used, _ := cidr.Mask.Size()
	maxNumberOfAddresses := int(math.Pow(2, float64(max-used))) - 2 // Do not allocate largest address or 0
	if maxNumberOfAddresses < 1 {
		return nil, errors.New("subnet is too small to contain a new device")
	}

	// Choose a random number that cannot be 0
	addressAttempt := rand.Intn(maxNumberOfAddresses) + 1
	return incrementIP(cidr.IP, uint(addressAttempt)), nil
}

func getNextIP(subnet string) (string, error) {

	serverIP, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	addr, err := chooseInitalIP(cidr)
	if err != nil {
		return "", err
	}

	lease, err := clientv3.NewLease(etcd).Grant(context.Background(), 3)
	if err != nil {
		return "", err
	}

	if serverIP.Equal(addr) {
		addr = incrementIP(addr, 1)
	}

	startIP := addr
	for {

		if serverIP.Equal(addr) {
			addr = incrementIP(addr, 1)
		}

		txn := etcd.Txn(context.Background())
		txn.If(
			clientv3util.KeyMissing(deviceRef+addr.String()),
			clientv3util.KeyMissing("ip-hold-"+addr.String()),
		)
		txn.Then(
			clientv3.OpPut("ip-hold-"+addr.String(), addr.String(), clientv3.WithLease(lease.ID)),
		)

		resp, err := txn.Commit()
		if err != nil {
			return "", err
		}

		if resp.Succeeded {
			return addr.String(), nil
		}

		addr = incrementIP(addr, 1)
		if cidr.Contains(addr) {
			continue
		} else {
			addr = incrementIP(cidr.IP, 1)
		}

		if addr.Equal(startIP) {
			return "", errors.New("unable to obtain ip lease, subnet is full")
		}

	}

}
