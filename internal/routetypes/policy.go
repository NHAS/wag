package routetypes

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type PolicyType uint16

const (
	ANY  = 0
	STOP = 0

	PUBLIC = 1 << PolicyType(iota) // Special directive, stop searching through the array, this is the end

	RANGE
	SINGLE
)

// Format
/*
struct range
{
	__u16 policy_type;
    __u16 proto;
    __u16 lower_port;
    __u16 upper_port;
};
*/
type Policy struct {
	PolicyType uint16
	Proto      uint16
	LowerPort  uint16
	UpperPort  uint16
}

func (p *Policy) Is(pt PolicyType) bool {
	if p.PolicyType == 0 && pt == 0 {
		return true
	}

	return p.PolicyType&uint16(pt) != 0
}
func (r Policy) Bytes() []byte {
	output := make([]byte, 8)
	binary.LittleEndian.PutUint16(output, r.PolicyType)
	binary.LittleEndian.PutUint16(output[2:], r.Proto)

	binary.LittleEndian.PutUint16(output[4:], r.LowerPort)
	binary.LittleEndian.PutUint16(output[6:], r.UpperPort)

	return output
}

func (r *Policy) Unpack(b []byte) error {
	if len(b) < 8 {
		return errors.New("too short")
	}

	r.PolicyType = binary.LittleEndian.Uint16(b[0:])

	r.Proto = binary.LittleEndian.Uint16(b[2:])
	r.LowerPort = binary.LittleEndian.Uint16(b[4:])
	r.UpperPort = binary.LittleEndian.Uint16(b[6:])

	return nil
}

func (r Policy) String() string {

	restrictionType := "mfa"

	if r.Is(PUBLIC) {
		restrictionType = "public"
	}

	if r.Is(STOP) {
		return fmt.Sprintf("%s stop", restrictionType)
	}

	if r.Is(SINGLE) {
		port := fmt.Sprintf("%d", r.LowerPort)
		if r.LowerPort == 0 {
			port = "any"
		}
		return fmt.Sprintf("%s %s/%s", restrictionType, port, lookupProtocol(r.Proto))
	}

	if r.Is(RANGE) {
		return fmt.Sprintf("%s %d-%d/%s", restrictionType, r.LowerPort, r.UpperPort, lookupProtocol(r.Proto))
	}

	return "unknown policy"
}
