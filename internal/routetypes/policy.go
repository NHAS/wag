package routetypes

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	STOP = uint16(iota) // Special directive, stop searching through the array, this is the end
	RANGE
	SINGLE
)

const (
	ANY = 0
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

func (r Policy) Bytes() []byte {
	output := make([]byte, 8)
	binary.LittleEndian.PutUint16(output, r.PolicyType)
	binary.LittleEndian.PutUint16(output[2:], r.Proto)

	binary.BigEndian.PutUint16(output[4:], r.LowerPort)
	binary.BigEndian.PutUint16(output[6:], r.UpperPort)

	return output
}

func (r *Policy) Unpack(b []byte) error {
	if len(b) < 8 {
		return errors.New("too short")
	}

	r.PolicyType = binary.LittleEndian.Uint16(b[0:])

	r.Proto = binary.LittleEndian.Uint16(b[2:])
	r.LowerPort = binary.BigEndian.Uint16(b[4:])
	r.UpperPort = binary.BigEndian.Uint16(b[6:])

	return nil
}

func (r Policy) String() string {

	return fmt.Sprintf("%d-%d/%s", r.LowerPort, r.UpperPort, lookupProtocol(r.Proto))
}
