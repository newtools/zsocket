package zsocket

import (
	"net"
)

type Tagging int

const (
	NotTagged    Tagging = 0
	Tagged       Tagging = 4
	DoubleTagged Tagging = 8
)

type Frame []byte

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

func (f *Frame) MACPayload() []byte {
	return (*f)[12+f.MACTagging()+2:]
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
