package fakeinterface

import (
	"github.com/nathanjsweet/zsocket/inet"
	"github.com/nathanjsweet/zsocket/nettypes"
)

func ICMPRequestReply(icmpType nettypes.ICMPType, code nettypes.ICMPCode) (nettypes.ICMP_P, uint16) {
	icmp := nettypes.ICMP_P(make([]byte, 64))
	icmp[0] = byte(icmpType)
	icmp[1] = byte(code)
	icmp[4] = 0x00
	icmp[5] = 0x00
	icmp[6] = 0x00
	icmp[7] = 0x00
	inet.PutShort(icmp[2:4], icmp.CalculateChecksum(64))
	return icmp, 64
}
