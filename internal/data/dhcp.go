package data

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

// https://gist.github.com/udhos/b468fbfd376aa0b655b6b0c539a88c03
func incrementIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func getNextIP(subnet string) (string, error) {

	serverIP, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	used, _ := cidr.Mask.Size()
	maxNumberOfAddresses := int(math.Pow(2, float64(32-used))) - 2 // Do not allocate largest address or 0
	if maxNumberOfAddresses < 1 {
		return "", errors.New("subnet is too small to contain a new device")
	}

	// Choose a random number that cannot be 0
	addressAttempt := rand.Intn(maxNumberOfAddresses) + 1
	addr := incrementIP(cidr.IP, uint(addressAttempt))

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
			clientv3util.KeyMissing("deviceref-"+addr.String()),
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
