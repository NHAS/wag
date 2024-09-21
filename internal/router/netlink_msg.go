package router

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type IfInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

type IfAddrmsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}
