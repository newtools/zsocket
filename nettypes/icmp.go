package nettypes

import (
	"fmt"
	"net"

	"github.com/nathanjsweet/zsocket/inet"
)

type ICMPType uint8

const (
	EchoReply              = ICMPType(0x00)
	DestinationUnreachable = ICMPType(0x03)
	RedirectMessage        = ICMPType(0x05)
	EchoRequest            = ICMPType(0x08)
	RouterAdvertisement    = ICMPType(0x09)
	RouterSolicitation     = ICMPType(0x0a)
	TimeExceeded           = ICMPType(0x0b)
	ParameterProblem       = ICMPType(0x0c)
	Timestamp              = ICMPType(0x0d)
	TimestampReply         = ICMPType(0x0e)
)

func (i ICMPType) String() string {
	switch i {
	case EchoReply:
		return "EchoReply"
	case DestinationUnreachable:
		return "DestinationUnreachable"
	case RedirectMessage:
		return "RedirectMessage"
	case EchoRequest:
		return "EchoRequest"
	case RouterAdvertisement:
		return "RouterAdvertisement"
	case RouterSolicitation:
		return "RouterSolicitation"
	case TimeExceeded:
		return "TimeExceeded"
	case ParameterProblem:
		return "ParameterProblem"
	case Timestamp:
		return "Timestamp"
	case TimestampReply:
		return "TimestampReply"
	default:
		return fmt.Sprintf("unkown type:%x", uint8(i))
	}
}

type ICMPCode uint8

func (i ICMPCode) String(typ ICMPType) string {
	switch typ {
	case EchoReply:
		return "EchoReply"
	case DestinationUnreachable:
		switch i {
		case 0x00:
			return "Destination network unreachable"
		case 0x01:
			return "Destination host unreachable"
		case 0x02:
			return "Destination protocol unreachable"
		case 0x03:
			return "Destination port unreachable"
		case 0x04:
			return "Fragmentation required, and DF flag set"
		case 0x05:
			return "Source route failed"
		case 0x06:
			return "Destination network unknown"
		case 0x07:
			return "Destination host unknown"
		case 0x08:
			return "Source host isolated"
		case 0x09:
			return "Network administratively prohibited"
		case 0x0a:
			return "Host administratively prohibited"
		case 0x0b:
			return "Network unreachable for ToS"
		case 0x0c:
			return "Host unreachable for ToS"
		case 0x0d:
			return "Communication administratively prohibited"
		case 0x0e:
			return "Host Precedence Violation"
		case 0x0f:
			return "Precedence cutoff in effect"
		}
	case RedirectMessage:
		switch i {
		case 0x00:
			return "Redirect Datagram for the Network"
		case 0x01:
			return "Redirect Datagram for the Host"
		case 0x02:
			return "Redirect Datagram for the ToS & network"
		case 0x03:
			return "Redirect Datagram for the ToS & host"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case EchoRequest:
		return "EchoRequest"
	case RouterAdvertisement:
		return "RouterAdvertisement"
	case RouterSolicitation:
		return "RouterSolicitation"
	case TimeExceeded:
		switch i {
		case 0x00:
			return "TTL expired in transit"
		case 0x01:
			return "Fragment reassembly time exceeded"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case ParameterProblem:
		switch i {
		case 0x00:
			return "Pointer indicates the error"
		case 0x01:
			return "Missing a required option"
		case 0x02:
			return "Bad length"
		default:
			return fmt.Sprintf("incorrect code set: %x", uint8(i))
		}
	case Timestamp:
		return "Timestamp"
	case TimestampReply:
		return "TimestampReply"
	}
	return fmt.Sprintf("unkown code:%x", uint8(i))
}

type ICMP_P []byte

func (p ICMP_P) IPProtocol() IPProtocol {
	return ICMP
}

func (p ICMP_P) Bytes() []byte {
	return p
}

func (p ICMP_P) String(frameLen uint16, indent int) string {
	typ := p.Type()
	pay, _ := p.Payload()
	ps := pay.String(typ, indent)
	s := fmt.Sprintf(padLeft("ICMP Len     : %d\n", "\t", indent), frameLen) +
		fmt.Sprintf(padLeft("Type         : %s\n", "\t", indent), typ) +
		fmt.Sprintf(padLeft("Code         : %s\n", "\t", indent), p.Code().String(typ)) +
		fmt.Sprintf(padLeft("Checksum     : %02x\n", "\t", indent), p.Checksum()) +
		fmt.Sprintf(padLeft("CalcChecksum : %02x\n", "\t", indent), inet.HToNSFS(p.CalculateChecksum(frameLen)))
	if len(ps) > 0 {
		s += fmt.Sprintf(padLeft("Payload      :\n%s", "\t", indent), ps)
	}
	return s
}

func (p ICMP_P) Type() ICMPType {
	return ICMPType(p[0])
}

func (p ICMP_P) Code() ICMPCode {
	return ICMPCode(p[1])
}

func (p ICMP_P) Checksum() uint16 {
	return inet.NToHS(p[2:4])
}

func (p ICMP_P) CalculateChecksum(frameLen uint16) uint16 {
	cs := uint32(inet.HostByteOrder.Uint16(p[0:2])) +
		uint32(inet.HostByteOrder.Uint16(p[4:6])) +
		uint32(inet.HostByteOrder.Uint16(p[6:8]))
	frameLen -= 8
	i := 8
	for ; frameLen > 1; i, frameLen = i+2, frameLen-2 {
		cs += uint32(inet.HostByteOrder.Uint16(p[i : i+2]))
		if cs&0x80000000 > 0 {
			cs = (cs & 0xffff) + (cs >> 16)
		}
	}
	if frameLen > 0 {
		cs += uint32(uint8(p[i]))
	}
	for cs>>16 > 0 {
		cs = (cs & 0xffff) + (cs >> 16)
	}
	return ^uint16(cs)
}

func (p ICMP_P) Payload() (ICMP_Payload, uint16) {
	return ICMP_Payload(p[4:]), 4
}

type ICMP_Payload []byte

func (pay ICMP_Payload) String(typ ICMPType, indent int) string {
	indent++
	switch typ {
	case RedirectMessage:
		return fmt.Sprintf(padLeft("IP Addr : %s\n", "\t", indent), net.IP(pay[4:8]).String())
	case Timestamp:
		fallthrough
	case TimestampReply:
		return fmt.Sprintf(padLeft("Identifier  : %d\n", "\t", indent), inet.NToHI(pay[4:6])) +
			fmt.Sprintf(padLeft("Seq Number  : %d\n", "\t", indent), inet.NToHI(pay[6:8])) +
			fmt.Sprintf(padLeft("Origin TS   : %d\n", "\t", indent), inet.NToHI(pay[8:12])) +
			fmt.Sprintf(padLeft("Receive TS  : %d\n", "\t", indent), inet.NToHI(pay[12:16])) +
			fmt.Sprintf(padLeft("Transmit TS : %d\n", "\t", indent), inet.NToHI(pay[16:20]))
	}
	return "\n"
}
