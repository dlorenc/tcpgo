package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	cIFF_TUN   = 0x0001
	cIFF_TAP   = 0x0002
	cIFF_NO_PI = 0x1000
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
}

var ourNetAddr net.HardwareAddr

var f *os.File

func main() {
	ourNetAddr, _ = net.ParseMAC("00:0c:29:6d:50:25")
	fmt.Println("ioctl")
	var err error
	f, err = os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	defer f.Close()
	if err != nil {
		panic(err)
	}

	var req ifReq
	copy(req.Name[:], "mytun")

	req.Flags = cIFF_TAP | cIFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		panic(errno)
	}

	var e EthHeader
	for {
		buf := make([]byte, 1600)
		_, err := f.Read(buf)
		if err != nil {
			panic(err)
		}
		// parse buf
		ParseEthHeader(&e, buf)
		fmt.Println("GOT ETH DATA: ", e.dmac, e.smac)
		if e.ethertype >= 1536 {
			switch e.ethertype {
			case EthPArp:
				fmt.Println("ARP")
				arpRcv(e.payload)
			case EthPIP:
				fmt.Println("IP")
			case EthPIPV6:
				fmt.Println("IPv6")
			default:
				fmt.Println("UNSUPPORTED")
			}
		} else {
			// len := ethertype
			// fmt.Println("LEN: ", len)
		}
	}
}

const ourIP = 167837951

func arpRcv(buf []byte) {
	var a ArpHeader

	ParseArpHeader(&a, buf)

	if a.hwtype != ArpEthernet {
		fmt.Println("UNSUPPORTED hwtype: ", a.hwtype)
		return
	}

	if a.protype != ArpIPV4 {
		fmt.Println("UNSUPPORTED PROTYPE: ", a.protype)
		return
	}

	var m ArpIPV4Message
	ParseArpIPV4Message(&m, buf[8:])

	fmt.Println("Got ARP DATA: ", m.dmac, printIP(m.sip), m.smac, printIP(m.dip), a.hwsize, a.prosize)

	if m.dip != ourIP {
		fmt.Println("Not for us")
		return
	}

	switch a.opcode {
	case ArpRequest:
		arpReply(m)
	default:
		fmt.Println("UNSUPPORTED OPCODE: ", a.opcode)
	}
}

func arpReply(r ArpIPV4Message) {
	var a ArpHeader
	a.opcode = ArpReply
	a.hwtype = ArpEthernet
	a.protype = ArpIPV4
	a.hwsize = 6
	a.prosize = 4

	var d ArpIPV4Message
	// Their source is our dest.
	d.dip = r.sip
	d.dmac = r.smac

	// Our IP/MAC is the new source.
	d.sip = ourIP
	copy(d.smac[:], ourNetAddr)

	a.data = d.Bytes()

	var hdr EthHeader
	hdr.dmac = d.dmac
	hdr.smac = d.smac
	hdr.ethertype = EthPArp
	hdr.payload = a.Bytes()

	b := hdr.Bytes()
	fmt.Println(b)
	if _, err := f.Write(b); err != nil {
		panic(err)
	}
}

func printIP(ip uint32) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ip)
	return fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
}
