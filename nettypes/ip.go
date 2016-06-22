package nettypes

import (
	"fmt"
	"net"

	"github.com/nathanjsweet/zsocket/inet"
)

type IPProtocol uint8

const (
	HOPOPT = 0x00
	ICMP   = 0x01
	IGMP   = 0x02
	GGP    = 0x03
	IPinIP = 0x04
	ST     = 0x05
	TCP    = 0x06
	UDP    = 0x11
)

func (p IPProtocol) String() string {
	switch p {
	case HOPOPT:
		return "HOPOPT"
	case ICMP:
		return "ICMP"
	case IGMP:
		return "IGMP"
	case GGP:
		return "GGP"
	case IPinIP:
		return "IPinIP"
	case ST:
		return "ST"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		return fmt.Sprintf("%x", byte(p))
	}
}

type IPv4_P []byte

func (i IPv4_P) String(frameLen uint32, indent int) string {
	return fmt.Sprintf(padLeft("IP Len   : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(padLeft("Version  : %d\n", "\t", indent), i.Version()) +
		fmt.Sprintf(padLeft("IHL      : %d\n", "\t", indent), i.IHL()) +
		fmt.Sprintf(padLeft("Length   : %d\n", "\t", indent), i.Length()) +
		fmt.Sprintf(padLeft("Id       : %d\n", "\t", indent), i.Id()) +
		fmt.Sprintf(padLeft("Flags    : %s\n", "\t", indent), i.FlagsString()) +
		fmt.Sprintf(padLeft("Frag Off : %d\n", "\t", indent), i.FragmentOffset()) +
		fmt.Sprintf(padLeft("TTL HC   : %d\n", "\t", indent), i.TTLHopCount()) +
		fmt.Sprintf(padLeft("Protocol : %s\n", "\t", indent), i.Protocol()) +
		fmt.Sprintf(padLeft("Checksum : %02x\n", "\t", indent), i.Checksum()) +
		fmt.Sprintf(padLeft("Calcsum  : %02x\n", "\t", indent), i.CalculateChecksum()) +
		fmt.Sprintf(padLeft("SourceIP : %s\n", "\t", indent), i.SourceIP()) +
		fmt.Sprintf(padLeft("DestIP   : %s\n", "\t", indent), i.DestinationIP()) +
		i.PayloadString(frameLen, indent)
}

func (i IPv4_P) PayloadString(frameLen uint32, indent int) string {
	p, off := i.Payload()
	frameLen -= off
	indent++
	switch i.Protocol() {
	case TCP:
		return TCP_P(p).String(frameLen, indent, i.SourceIP(), i.DestinationIP())
	case ICMP:
		return ICMP_P(p).String(frameLen, indent)
	default:
		indent--
		return padLeft("unrecognized ip protocol...\n", "\t", indent)
	}
}

func (i IPv4_P) Version() uint8 {
	return uint8(i[0] >> 4)
}

func (i IPv4_P) IHL() uint8 {
	return uint8(i[0] & 0x0f)
}

func (i IPv4_P) Length() uint16 {
	return inet.NToHS(i[2:4])
}

func (i IPv4_P) Id() uint16 {
	return inet.NToHS(i[4:6])
}

func (i IPv4_P) Flags() uint8 {
	return uint8(i[6] >> 5)
}

func (i IPv4_P) FlagsString() string {
	s := ""
	f := i.Flags()
	if f&0x01 == 0x01 {
		s += "MF"
	}
	if f&0x02 == 0x02 {
		s += "DF"
	}
	return s
}

func (i IPv4_P) FragmentOffset() uint16 {
	return inet.NToHS([]byte{i[6] & 0x1f, i[7]})
}

func (i IPv4_P) TTLHopCount() uint8 {
	return uint8(i[8])
}

func (i IPv4_P) Protocol() IPProtocol {
	return IPProtocol(i[9])
}

func (i IPv4_P) Checksum() uint16 {
	return inet.NToHS(i[10:12])
}

func (i IPv4_P) CalculateChecksum() uint16 {
	cs := uint32(inet.HostByteOrder.Uint16(i[0:2])) +
		uint32(inet.HostByteOrder.Uint16(i[2:4])) +
		uint32(inet.HostByteOrder.Uint16(i[4:6])) +
		uint32(inet.HostByteOrder.Uint16(i[6:8])) +
		uint32(inet.HostByteOrder.Uint16(i[8:10])) +
		uint32(inet.HostByteOrder.Uint16(i[12:14])) +
		uint32(inet.HostByteOrder.Uint16(i[14:16])) +
		uint32(inet.HostByteOrder.Uint16(i[16:18])) +
		uint32(inet.HostByteOrder.Uint16(i[18:20]))
	index := 20
	for t, l := 0, int(i.IHL()-5); t < l; t++ {
		cs += uint32(inet.HostByteOrder.Uint16(i[index : index+2]))
		index += 2
		cs += uint32(inet.HostByteOrder.Uint16(i[index : index+2]))
		index += 2
	}
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (i IPv4_P) PacketCorrupt() bool {
	return i.Checksum() == i.CalculateChecksum()
}

func (i IPv4_P) SourceIP() net.IP {
	return net.IP(i[12:16])
}

func (i IPv4_P) DestinationIP() net.IP {
	return net.IP(i[16:20])
}

func (i IPv4_P) Payload() ([]byte, uint32) {
	off := uint32(i.IHL() * 4)
	return i[off:], off
}
