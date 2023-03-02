package routetypes

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Format
/*
struct range
{
    __u16 proto;
    __u16 lower_port;
    __u16 upper_port;

    __u16 PAD;
};
*/
type Range struct {
	Proto     uint16
	LowerPort uint16
	UpperPort uint16
}

func (r Range) Bytes() []byte {
	output := make([]byte, 8)
	binary.BigEndian.PutUint16(output[0:2], r.Proto)

	binary.BigEndian.PutUint16(output[2:], r.LowerPort)
	binary.BigEndian.PutUint16(output[4:], r.UpperPort)

	return output
}

func (r *Range) Unpack(b []byte) error {
	if len(b) < 8 {
		return errors.New("too short")
	}

	r.Proto = binary.BigEndian.Uint16(b[0:2])
	r.LowerPort = binary.BigEndian.Uint16(b[2:4])
	r.UpperPort = binary.BigEndian.Uint16(b[4:6])

	return nil
}

func (r Range) String() string {
	return fmt.Sprintf("proto %d, %d-%d", r.Proto, r.LowerPort, r.UpperPort)
}
