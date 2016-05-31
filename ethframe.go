package zsocket

import (
	"fmt"
	"net"
)

type EthType [2]byte

var (
	All                 = EthType{0x00, 0x03}
	IPv4                = EthType{0x08, 0x00}
	ARP                 = EthType{0x08, 0x06}
	WakeOnLAN           = EthType{0x08, 0x42}
	TRILL               = EthType{0x22, 0xF3}
	DECnetPhase4        = EthType{0x60, 0x03}
	RARP                = EthType{0x80, 0x35}
	AppleTalk           = EthType{0x80, 0x9B}
	AARP                = EthType{0x80, 0xF3}
	IPX1                = EthType{0x81, 0x37}
	IPX2                = EthType{0x81, 0x38}
	QNXQnet             = EthType{0x82, 0x04}
	IPv6                = EthType{0x86, 0xDD}
	EthernetFlowControl = EthType{0x88, 0x08}
	IEEE802_3           = EthType{0x88, 0x09}
	CobraNet            = EthType{0x88, 0x19}
	MPLSUnicast         = EthType{0x88, 0x47}
	MPLSMulticast       = EthType{0x88, 0x48}
	PPPoEDiscovery      = EthType{0x88, 0x63}
	PPPoESession        = EthType{0x88, 0x64}
	JumboFrames         = EthType{0x88, 0x70}
	HomePlug1_0MME      = EthType{0x88, 0x7B}
	IEEE802_1X          = EthType{0x88, 0x8E}
	PROFINET            = EthType{0x88, 0x92}
	HyperSCSI           = EthType{0x88, 0x9A}
	AoE                 = EthType{0x88, 0xA2}
	EtherCAT            = EthType{0x88, 0xA4}
	EthernetPowerlink   = EthType{0x88, 0xAB}
	LLDP                = EthType{0x88, 0xCC}
	SERCOS3             = EthType{0x88, 0xCD}
	HomePlugAVMME       = EthType{0x88, 0xE1}
	MRP                 = EthType{0x88, 0xE3}
	IEEE802_1AE         = EthType{0x88, 0xE5}
	IEEE1588            = EthType{0x88, 0xF7}
	IEEE802_1ag         = EthType{0x89, 0x02}
	FCoE                = EthType{0x89, 0x06}
	FCoEInit            = EthType{0x89, 0x14}
	RoCE                = EthType{0x89, 0x15}
	CTP                 = EthType{0x90, 0x00}
	VeritasLLT          = EthType{0xCA, 0xFE}
)

func (e EthType) String() string {
	switch e {
	case All:
		return "All"
	case IPv4:
		return "IPv4"
	case ARP:
		return "ARP"
	case WakeOnLAN:
		return "WakeOnLAN"
	case TRILL:
		return "TRILL"
	case DECnetPhase4:
		return "DECnetPhase4"
	case RARP:
		return "RARP"
	case AppleTalk:
		return "AppleTalk"
	case AARP:
		return "AARP"
	case IPX1:
		return "IPX1"
	case IPX2:
		return "IPX2"
	case QNXQnet:
		return "QNXQnet"
	case IPv6:
		return "IPv6"
	case EthernetFlowControl:
		return "EthernetFlowControl"
	case IEEE802_3:
		return "IEEE802_3"
	case CobraNet:
		return "CobraNet"
	case MPLSUnicast:
		return "MPLSUnicast"
	case MPLSMulticast:
		return "MPLSMulticast"
	case PPPoEDiscovery:
		return "PPPoEDiscovery"
	case PPPoESession:
		return "PPPoESession"
	case JumboFrames:
		return "JumboFrames"
	case HomePlug1_0MME:
		return "HomePlug1_0MME"
	case IEEE802_1X:
		return "IEEE802_1X"
	case PROFINET:
		return "PROFINET"
	case HyperSCSI:
		return "HyperSCSI"
	case AoE:
		return "AoE"
	case EtherCAT:
		return "EtherCAT"
	case EthernetPowerlink:
		return "EthernetPowerlink"
	case LLDP:
		return "LLDP"
	case SERCOS3:
		return "SERCOS3"
	case HomePlugAVMME:
		return "HomePlugAVMME"
	case MRP:
		return "MRP"
	case IEEE802_1AE:
		return "IEEE802_1AE"
	case IEEE1588:
		return "IEEE1588"
	case IEEE802_1ag:
		return "IEEE802_1ag"
	case FCoE:
		return "FCoE"
	case FCoEInit:
		return "FCoEInit"
	case RoCE:
		return "RoCE"
	case CTP:
		return "CTP"
	case VeritasLLT:
		return "VeritasLLT"
	default:
		return fmt.Sprintf("unknown type:%02x", e[0:2])
	}
}

type Tagging int

const (
	NotTagged    Tagging = 0
	Tagged       Tagging = 4
	DoubleTagged Tagging = 8
)

type Frame []byte

func (f *Frame) String(l int) string {
	return fmt.Sprintf("Frame Len  : %d\n", l) +
		fmt.Sprintf("MAC Source : %s\n", f.MACSource()) +
		fmt.Sprintf("MAC Dest   : %s\n", f.MACDestination()) +
		fmt.Sprintf("MAC Type   : %s\n", f.MACEthertype()) +
		f.GetPayString(l)
}

func (f *Frame) MACSource() net.HardwareAddr {
	return net.HardwareAddr((*f)[6:12])
}

func (f *Frame) MACDestination() net.HardwareAddr {
	return net.HardwareAddr((*f)[:6])
}

func (f *Frame) MACTagging() Tagging {
	b1, b2 := (*f)[12], (*f)[13]
	if b1 == 0x81 && b2 == 0x00 {
		b3, b4 := (*f)[16], (*f)[17]
		if b3 == 0x81 && b4 == 0x00 {
			return DoubleTagged
		}
		return Tagged
	}
	if (b1 == 0x91 || b1 == 0x92) && b2 == 0x00 {
		return DoubleTagged
	}
	if b1 == 0x88 && b2 == 0xA8 {
		return DoubleTagged
	}
	return NotTagged
}

func (f *Frame) MACEthertype() EthType {
	pos := 12 + f.MACTagging()
	return EthType{(*f)[pos], (*f)[pos+1]}
}

func (f *Frame) MACPayload() ([]byte, int) {
	off := 12 + int(f.MACTagging()) + 2
	return (*f)[off:], off
}

func (f *Frame) GetPayString(frameLen int) string {
	p, off := f.MACPayload()
	frameLen -= off
	switch f.MACEthertype() {
	case ARP:
		return ARP_P(p).String()
	case IPv4:
		return IPv4_P(p).String(frameLen)
	default:
		return "unknown eth payload...\n"
	}
}

func IsMACBroadcast(addr net.HardwareAddr) bool {
	return addr[0] == 0xFF && addr[1] == 0xFF && addr[2] == 0xFF && addr[3] == 0xFF && addr[4] == 0xFF && addr[5] == 0xFF
}

func IsMACMulticastIPv4(addr net.HardwareAddr) bool {
	return addr[0] == 0x01 && addr[1] == 0x00 && addr[2] == 0x5E
}

func IsMACMulticastIPv6(addr net.HardwareAddr) bool {
	return addr[0] == 0x33 && addr[1] == 0x33
}
