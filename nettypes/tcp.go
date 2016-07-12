package nettypes

import (
	"fmt"
	"net"

	"github.com/nathanjsweet/zsocket/inet"
)

type TCPControl uint16

const (
	NS  = TCPControl(0x01 << 0)
	CWR = TCPControl(0x01 << 1)
	ECE = TCPControl(0x01 << 2)
	URG = TCPControl(0x01 << 3)
	ACK = TCPControl(0x01 << 4)
	PSH = TCPControl(0x01 << 5)
	RST = TCPControl(0x01 << 6)
	SYN = TCPControl(0x01 << 7)
	FIN = TCPControl(0x01 << 8)
)

// this is set `hosttonetwork.go`
// because it depends on an init func
var _PROTO_TCP uint32

func init() {
	_PROTO_TCP = inet.HToNIFI(uint32(TCP))
}

func (c TCPControl) String() string {
	s := ""
	if c&NS == NS {
		s += "NS|"
	}
	if c&CWR == CWR {
		s += "CWR|"
	}
	if c&ECE == ECE {
		s += "ECE|"
	}
	if c&URG == URG {
		s += "URG|"
	}
	if c&ACK == ACK {
		s += "ACK|"
	}
	if c&PSH == PSH {
		s += "PSH|"
	}
	if c&RST == RST {
		s += "RST|"
	}
	if c&SYN == SYN {
		s += "SYN|"
	}
	if c&FIN == FIN {
		s += "FIN|"
	}
	return s[:len(s)-1]
}

type TCP_P []byte

func (t TCP_P) IPProtocol() IPProtocol {
	return TCP
}

func (t TCP_P) Bytes() []byte {
	return t
}

func (t TCP_P) String(frameLen uint16, indent int, srcAddr, destAddr net.IP) string {
	return fmt.Sprintf(padLeft("TCP Len      : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(padLeft("Source Port  : %d\n", "\t", indent), t.SourcePort()) +
		fmt.Sprintf(padLeft("Dest Port    : %d\n", "\t", indent), t.DestinationPort()) +
		fmt.Sprintf(padLeft("Seq Number   : %d\n", "\t", indent), t.SequenceNumber()) +
		fmt.Sprintf(padLeft("ACK Number   : %d\n", "\t", indent), t.AckNumber()) +
		fmt.Sprintf(padLeft("Data Offset  : %d\n", "\t", indent), t.DataOffset()) +
		fmt.Sprintf(padLeft("Controls     : %s\n", "\t", indent), t.Controls()) +
		fmt.Sprintf(padLeft("Window Size  : %d\n", "\t", indent), t.WindowSize()) +
		fmt.Sprintf(padLeft("Checksum     : %02x\n", "\t", indent), t.Checksum()) +
		fmt.Sprintf(padLeft("CalcChecksum : %02x\n", "\t", indent), inet.HToNSFS(t.CalculateChecksum(frameLen, srcAddr, destAddr))) +
		fmt.Sprintf(padLeft("URG Pointer  : %d\n", "\t", indent), t.UrgPointer())
}

func (t TCP_P) SourcePort() uint16 {
	return inet.NToHS(t[0:2])
}

func (t TCP_P) DestinationPort() uint16 {
	return inet.NToHS(t[2:4])
}

func (t TCP_P) SequenceNumber() uint32 {
	return inet.NToHI(t[4:8])
}

func (t TCP_P) AckNumber() uint32 {
	return inet.NToHI(t[8:12])
}

func (t TCP_P) DataOffset() uint8 {
	return uint8(t[12] >> 4)
}

func (t TCP_P) Controls() TCPControl {
	var c TCPControl = 0
	if t[12]&0x1 == 0x1 {
		c |= NS
	}
	if t[13]&0x80 == 0x80 {
		c |= CWR
	}
	if t[13]&0x40 == 0x40 {
		c |= ECE
	}
	if t[13]&0x20 == 0x20 {
		c |= ECE
	}
	if t[13]&0x20 == 0x20 {
		c |= ECE
	}
	if t[13]&0x10 == 0x10 {
		c |= ACK
	}
	if t[13]&0x8 == 0x8 {
		c |= PSH
	}
	if t[13]&0x4 == 0x4 {
		c |= RST
	}
	if t[13]&0x2 == 0x2 {
		c |= SYN
	}
	if t[13]&0x1 == 0x1 {
		c |= FIN
	}
	return c
}

func (t TCP_P) WindowSize() uint16 {
	return inet.NToHS(t[14:16])
}

func (t TCP_P) Checksum() uint16 {
	return inet.NToHS(t[16:18])
}

func (t TCP_P) CalculateChecksum(frameLen uint16, srcAddr, destAddr net.IP) uint16 {
	cs := uint32(inet.HostByteOrder.Uint16(t[0:2])) +
		uint32(inet.HostByteOrder.Uint16(t[2:4])) +
		uint32(inet.HostByteOrder.Uint16(t[4:6])) +
		uint32(inet.HostByteOrder.Uint16(t[6:8])) +
		uint32(inet.HostByteOrder.Uint16(t[8:10])) +
		uint32(inet.HostByteOrder.Uint16(t[10:12])) +
		uint32(inet.HostByteOrder.Uint16(t[12:14])) +
		uint32(inet.HostByteOrder.Uint16(t[14:16])) +
		uint32(inet.HostByteOrder.Uint16(t[18:20]))
	fl := frameLen - 20
	i := 20
	for ; fl > 1; i, fl = i+2, fl-2 {
		cs += uint32(inet.HostByteOrder.Uint16(t[i : i+2]))
		if cs&0x80000000 > 0 {
			cs = (cs & 0xffff) + (cs >> 16)
		}
	}
	if fl > 0 {
		cs += uint32(uint8(t[i]))
	}
	cs += uint32(inet.HostByteOrder.Uint16(srcAddr[0:2]))
	cs += uint32(inet.HostByteOrder.Uint16(srcAddr[2:4]))
	cs += uint32(inet.HostByteOrder.Uint16(destAddr[0:2]))
	cs += uint32(inet.HostByteOrder.Uint16(destAddr[2:4]))
	cs += _PROTO_TCP
	cs += inet.HToNIFI(uint32(frameLen))
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (t TCP_P) SetChecksum(v uint16) {
	inet.PutShort(t[16:18], v)
}

func (t TCP_P) UrgPointer() uint16 {
	return inet.NToHS(t[18:20])
}

func (t TCP_P) Payload() ([]byte, uint16) {
	off := uint16(t.DataOffset() * 4)
	return t[off:], off
}
