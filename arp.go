package main

import "encoding/binary"

const (
	ArpEthernet = 0x0001
	ArpRequest  = 0x0001
	ArpReply    = 0x0002
	ArpIPV4     = 0x0800
)

type ArpHeader struct {
	hwtype  uint16
	protype uint16
	hwsize  byte
	prosize byte
	opcode  uint16
	data    []byte
}

func ParseArpHeader(a *ArpHeader, buf []byte) {
	a.hwtype = binary.BigEndian.Uint16(buf[0:2])
	a.protype = binary.BigEndian.Uint16(buf[2:4])
	a.hwsize = buf[4]
	a.prosize = buf[5]
	a.opcode = binary.BigEndian.Uint16(buf[6:8])
	a.data = buf[8:]
}

func (a *ArpHeader) Bytes() []byte {
	var b = make([]byte, 8+len(a.data))
	binary.BigEndian.PutUint16(b[0:2], a.hwtype)
	binary.BigEndian.PutUint16(b[2:4], a.protype)
	b[4] = a.hwsize
	b[5] = a.prosize
	binary.BigEndian.PutUint16(b[6:8], a.opcode)
	copy(b[8:], a.data)
	return b
}

type ArpIPV4Message struct {
	smac [6]byte
	sip  uint32
	dmac [6]byte
	dip  uint32
}

func (a *ArpIPV4Message) Bytes() []byte {
	var b = make([]byte, 20)
	copy(b[0:6], a.smac[:])
	binary.BigEndian.PutUint32(b[6:10], a.sip)
	copy(b[10:16], a.dmac[:])
	binary.BigEndian.PutUint32(b[16:20], a.dip)
	return b
}

func ParseArpIPV4Message(m *ArpIPV4Message, buf []byte) {
	copy(m.smac[:], buf[0:6])
	m.sip = binary.BigEndian.Uint32(buf[6:10])
	copy(m.dmac[:], buf[10:16])
	m.dip = binary.BigEndian.Uint32(buf[16:20])
}
