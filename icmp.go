package zsocket

import (
	"fmt"
	"net"
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

func (p ICMP_P) String() string {
	typ := p.Type()
	pay := p.Payload().String(typ)
	s := fmt.Sprintf("\t\tType         : %s\n", typ) +
		fmt.Sprintf("\t\tCode         : %s\n", p.Code().String(typ)) +
		fmt.Sprintf("\t\tChecksum     : %02x\n", p.Checksum()) +
		fmt.Sprintf("\t\tCalcChecksum : %02x\n", p.CalculateChecksum())
	if len(pay) > 0 {
		s += fmt.Sprintf("\t\tPayload      :\n%s", pay)
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
	return hostToNetwork.ntohs(p[2:4])
}

func (p ICMP_P) CalculateChecksum() uint16 {
	cs := hostToNetwork.htons(p[0:2]) +
		hostToNetwork.htons(p[4:6]) +
		hostToNetwork.htons(p[6:8])
	cs = (cs & 0xffff) + (cs >> 16)
	return ^cs
}

func (p ICMP_P) Payload() ICMP_Payload {
	return ICMP_Payload(p[4:])
}

type ICMP_Payload []byte

func (pay ICMP_Payload) String(typ ICMPType) string {
	switch typ {
	case RedirectMessage:
		return fmt.Sprintf("\t\t\tIP Addr : %s\n", net.IP(pay[4:8]).String())
	case Timestamp:
		fallthrough
	case TimestampReply:
		return fmt.Sprintf("\t\t\tIdentifier  : %d", hostToNetwork.ntohi(pay[4:6])) +
			fmt.Sprintf("\t\t\tSeq Number  : %d", hostToNetwork.ntohi(pay[6:8])) +
			fmt.Sprintf("\t\t\tOrigin TS   : %d", hostToNetwork.ntohi(pay[8:12])) +
			fmt.Sprintf("\t\t\tReceive TS  : %d", hostToNetwork.ntohi(pay[12:16])) +
			fmt.Sprintf("\t\t\tTransmit TS : %d", hostToNetwork.ntohi(pay[16:20]))
	}
	return ""
}
