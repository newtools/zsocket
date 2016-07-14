package fakeinterface

import "github.com/nathanjsweet/zsocket/nettypes"

func ICMPRequestReply(icmpType nettypes.ICMPType, code nettypes.ICMPCode, pay []byte, payL uint16) (nettypes.ICMP_P, uint16) {
	packetSize := 4 + payL
	icmp := nettypes.ICMP_P(make([]byte, packetSize))
	icmp[0] = byte(icmpType)
	icmp[1] = byte(code)
	copy(icmp[4:], pay[:payL])
	return icmp, packetSize
}
