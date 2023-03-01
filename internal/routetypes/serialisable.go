package routetypes

type Serial interface {
	Bytes() []byte
	Unpack(b []byte) error
}
