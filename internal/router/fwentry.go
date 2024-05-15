package router

import (
	"encoding/binary"
	"errors"
)

// Firewall entry for a device
type fwentry struct {
	sessionExpiry  uint64
	lastPacketTime uint64

	// Hash of username (sha1 20 bytes)
	// Essentially allows us to compress all usernames, if collisions are a problem in the future we'll move to sha256 or xxhash
	user_id [20]byte

	pad uint32

	associatedNode uint64
}

func (d fwentry) Size() int {
	return 48 // 8 + 8 + 20 + 4 + 8
}

func (d fwentry) Bytes() []byte {

	output := make([]byte, 48)

	binary.LittleEndian.PutUint64(output[0:8], d.sessionExpiry)
	binary.LittleEndian.PutUint64(output[8:16], d.lastPacketTime)

	copy(output[16:36], d.user_id[:])

	binary.LittleEndian.PutUint32(output[36:], d.pad)
	binary.LittleEndian.PutUint64(output[40:], d.associatedNode)

	return output
}

func (d *fwentry) Unpack(b []byte) error {
	if len(b) != 48 {
		return errors.New("firewall entry is too short")
	}

	d.sessionExpiry = binary.LittleEndian.Uint64(b[:8])
	d.lastPacketTime = binary.LittleEndian.Uint64(b[8:16])

	copy(d.user_id[:], b[16:36])

	d.pad = binary.LittleEndian.Uint32(b[36:])
	d.associatedNode = binary.LittleEndian.Uint64(b[40:])

	return nil
}
