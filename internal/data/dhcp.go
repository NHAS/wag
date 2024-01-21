package data

import (
	"context"
	"fmt"
	"net"
	"slices"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// This is almost certainly unsafe from splicing during multiple client registration
func allocateIPAddress(subnet string) (string, error) {

	// Retrieve the list of allocated IPs
	allocatedIPs, err := getAllocatedIPs()
	if err != nil {
		return "", err
	}

	// Find an unallocated IP address within the given subnet
	ip, err := findUnallocatedIP(subnet, allocatedIPs)
	if err != nil {
		return "", err
	}

	// Mark the selected IP as allocated
	if err := markIPAsAllocated(ip); err != nil {
		return "", err
	}

	return ip, nil
}

func getAllocatedIPs() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := etcd.Get(ctx, "allocated_ips", clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	var allocatedIPs []string
	for _, kv := range resp.Kvs {
		allocatedIPs = append(allocatedIPs, string(kv.Value))
	}

	return allocatedIPs, nil
}

func findUnallocatedIP(subnet string, allocatedIPs []string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// Check if the IP is unallocated

		if !slices.Contains(allocatedIPs, ip.String()) {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no available unallocated IP addresses in the subnet")
}

func markIPAsAllocated(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := etcd.Put(ctx, fmt.Sprintf("allocated_ips/%s", ip), ip)
	return err
}

func markIPAsUnallocated(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := etcd.Delete(ctx, fmt.Sprintf("allocated_ips/%s", ip))
	return err
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
