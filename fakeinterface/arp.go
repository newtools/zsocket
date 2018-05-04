package fakeinterface

import (
	"encoding/binary"
	"net"

	"github.com/newtools/zsocket/nettypes"
)

func ARPPacket(operation nettypes.ARPOperation, proto nettypes.EthType, senderHA net.HardwareAddr, senderIP *net.IPAddr, targetHA net.HardwareAddr, targetIP *net.IPAddr) (nettypes.ARP_P, uint16) {
	l := uint16(28)
	arp := nettypes.ARP_P(make([]byte, l))
	binary.BigEndian.PutUint16(arp[0:2], 1)
	arp[2] = proto[0]
	arp[3] = proto[1]
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], uint16(operation))
	copy(arp[8:14], senderHA)
	copy(arp[14:18], senderIP.IP)
	copy(arp[18:24], targetHA)
	copy(arp[24:28], targetIP.IP)
	return arp, l
}
