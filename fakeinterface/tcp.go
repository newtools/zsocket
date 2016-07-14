package fakeinterface

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/nathanjsweet/zsocket/nettypes"
)

const _STARTING_SEQ_NUM = 23451

var seqNum uint32 = _STARTING_SEQ_NUM

func TCPPacket(sourcePort, destPort uint16, seqNum, ackNum uint32, flags nettypes.TCPControl, windowSize, urgPointer uint16, pay []byte, len uint16) (nettypes.TCP_P, uint16) {
	l := 20 + len
	tcp := nettypes.TCP_P(make([]byte, l))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destPort)
	binary.BigEndian.PutUint32(tcp[4:8], seqNum)
	binary.BigEndian.PutUint32(tcp[8:12], ackNum)
	dOff := byte(0x50)
	if flags&nettypes.NS == nettypes.NS {
		dOff = dOff | 0x1
	}
	tcp[12] = dOff
	flag := byte(0x0)
	switch {
	case flags&nettypes.CWR == nettypes.CWR:
		flag = flag | 0x80
	case flags&nettypes.ECE == nettypes.ECE:
		flag = flag | 0x40
	case flags&nettypes.URG == nettypes.URG:
		flag = flag | 0x20
	case flags&nettypes.ACK == nettypes.ACK:
		flag = flag | 0x10
	case flags&nettypes.PSH == nettypes.PSH:
		flag = flag | 0x08
	case flags&nettypes.RST == nettypes.RST:
		flag = flag | 0x04
	case flags&nettypes.SYN == nettypes.SYN:
		flag = flag | 0x02
	case flags&nettypes.FIN == nettypes.FIN:
		flag = flag | 0x01
	}
	tcp[13] = flag
	binary.BigEndian.PutUint16(tcp[14:16], windowSize)
	binary.BigEndian.PutUint16(tcp[18:20], urgPointer)
	copy(tcp[20:], pay[:len])
	return tcp, l
}

func getNextSeqNum() uint32 {
	n := atomic.AddUint32(&seqNum, 1)
	if n <= 65535 {
		return n
	}
	atomic.CompareAndSwapUint32(&seqNum, n, _STARTING_SEQ_NUM)
	return getNextSeqNum()
}
