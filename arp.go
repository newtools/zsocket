package zsocket

import (
	"fmt"
	"net"
)

type ARP_P []byte

func (a ARP_P) String() string {
	return fmt.Sprintf("\tHtype : %02x\n", a.HardwareType()) +
		fmt.Sprintf("\tPtype : %02x\n", a.ProtocolType()) +
		fmt.Sprintf("\tHlen  : %d\n", a.Hlen()) +
		fmt.Sprintf("\tPlen  : %d\n", a.Plen()) +
		fmt.Sprintf("\tOper  : %d\n", a.Operation()) +
		fmt.Sprintf("\tSHA   : %s\n", a.SHA()) +
		fmt.Sprintf("\tSPA   : %s\n", a.SPA()) +
		fmt.Sprintf("\tTHA   : %s\n", a.THA()) +
		fmt.Sprintf("\tTPA   : %s\n", a.TPA())
}

func (a ARP_P) HardwareType() uint16 {
	return hostToNetwork.ntohs(a[0:2])
}

func (a ARP_P) ProtocolType() uint16 {
	return hostToNetwork.ntohs(a[2:4])
}

func (a ARP_P) Hlen() uint8 {
	return uint8(a[4])
}

func (a ARP_P) Plen() uint8 {
	return uint8(a[5])
}

func (a ARP_P) Operation() uint16 {
	return hostToNetwork.ntohs(a[6:8])
}

func (a ARP_P) SHA() net.HardwareAddr {
	return net.HardwareAddr(a[8:14])
}

func (a ARP_P) SPA() net.IP {
	return net.IP(a[14:18])
}

func (a ARP_P) THA() net.HardwareAddr {
	return net.HardwareAddr(a[18:24])
}

func (a ARP_P) TPA() net.IP {
	return net.IP(a[24:28])
}
