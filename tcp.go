package zsocket

import "fmt"

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

func (t TCP_P) String() string {
	return fmt.Sprintf("\t\tSource Port  : %d\n", t.SourcePort()) +
		fmt.Sprintf("\t\tDest Port    : %d\n", t.DestinationPort()) +
		fmt.Sprintf("\t\tSeq Number   : %d\n", t.SequenceNumber()) +
		fmt.Sprintf("\t\tACK Number   : %d\n", t.AckNumber()) +
		fmt.Sprintf("\t\tData Offset  : %d\n", t.DataOffset()) +
		fmt.Sprintf("\t\tControls     : %s\n", t.Controls()) +
		fmt.Sprintf("\t\tWindow Size  : %d\n", t.WindowSize()) +
		fmt.Sprintf("\t\tChecksum     : %02x\n", t.Checksum()) +
		fmt.Sprintf("\t\tCalcChecksum : %02x\n", t.CalculateChecksum()) +
		fmt.Sprintf("\t\tURG Pointer  : %d\n", t.UrgPointer())
}

func (t TCP_P) SourcePort() uint16 {
	return hostToNetwork.ntohs(t[0:2])
}

func (t TCP_P) DestinationPort() uint16 {
	return hostToNetwork.ntohs(t[2:4])
}

func (t TCP_P) SequenceNumber() uint32 {
	return hostToNetwork.ntohi(t[4:8])
}

func (t TCP_P) AckNumber() uint32 {
	return hostToNetwork.ntohi(t[8:12])
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
	return hostToNetwork.ntohs(t[14:16])
}

func (t TCP_P) Checksum() uint16 {
	return hostToNetwork.ntohs(t[16:18])
}

func (t TCP_P) CalculateChecksum() uint16 {
	cs := uint32(hostToNetwork.htons(t[0:2])) +
		uint32(hostToNetwork.htons(t[2:4])) +
		uint32(hostToNetwork.htons(t[4:6])) +
		uint32(hostToNetwork.htons(t[6:8])) +
		uint32(hostToNetwork.htons(t[8:10])) +
		uint32(hostToNetwork.htons(t[10:12])) +
		uint32(hostToNetwork.htons(t[12:14])) +
		uint32(hostToNetwork.htons(t[14:16])) +
		uint32(hostToNetwork.htons(t[18:20]))
	index := 20
	for i, l := 0, int(t.DataOffset()-5); i < l; i++ {
		cs += uint32(hostToNetwork.htons(t[index : index+2]))
		index += 2
		cs += uint32(hostToNetwork.htons(t[index : index+2]))
		index += 2
	}
	csum := uint16(cs&0xffff) +
		uint16(cs>>16)
	csum = ^csum
	if csum == 0x00 {
		csum = 0xffff
	}
	return csum
}

func (t TCP_P) UrgPointer() uint16 {
	return hostToNetwork.ntohs(t[18:20])
}

func (t TCP_P) Payload(len int) []byte {
	off := int(t.DataOffset() * 4)
	return t[off : off+len]
}
