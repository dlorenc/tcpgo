package main

import (
	"encoding/binary"
)

const (
	EthPArp  = 0x0806
	EthPIP   = 0x0800
	EthPIPV6 = 0x86DD
)

type EthHeader struct {
	dmac      [6]byte
	smac      [6]byte
	ethertype uint16
	payload   []byte
}

func ParseEthHeader(e *EthHeader, buf []byte) {
	copy(e.dmac[:], buf[0:6])
	copy(e.smac[:], buf[6:12])
	e.ethertype = binary.BigEndian.Uint16(buf[12:14])
	e.payload = buf[14:]
}

func (e *EthHeader) Bytes() []byte {
	var b = make([]byte, 14+len(e.payload))
	copy(b[0:6], e.dmac[:])
	copy(b[6:12], e.smac[:])
	binary.BigEndian.PutUint16(b[12:14], e.ethertype)
	copy(b[14:], e.payload)
	return b
}
