package zsocket

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	ENABLE_RX = 1
	ENABLE_TX = 2
)

const (
	_ETH_ALEN = 6

	_PACKET_VERSION = 0xa
	_PACKET_RX_RING = 0x5
	_PACKET_TX_RING = 0xd

	_TPACKET_V1 = 0

	_TPACKET_ALIGNMENT = 16
	/* rx status */
	_TP_STATUS_KERNEL = 0
	_TP_STATUS_USER   = 1 << 0
	/* tx status */
	_TP_STATUS_AVAILABLE    = 0
	_TP_STATUS_SEND_REQUEST = (1 << 0)
	_TP_STATUS_SENDING      = (1 << 1)
	/* poll events */
	_POLLIN  = 0x01
	_POLLOUT = 0x04
	_POLLERR = 0x08
)

var (
	_TP_MAC_START     int
	_TP_MAC_STOP      int
	_TP_LEN_START     int
	_TP_LEN_STOP      int
	_TP_SNAPLEN_START int
	_TP_SNAPLEN_STOP  int
	_TP_NET_START     int
	_TP_NET_STOP      int
	_TP_SEC_START     int
	_TP_SEC_STOP      int
	_TP_USEC_START    int
	_TP_USEC_STOP     int

	_TX_START int
)

// the top of every frame in the ring buffer looks like this:
//struct tpacket_hdr {
//         unsigned long   tp_status;
//         unsigned int    tp_len;
//         unsigned int    tp_snaplen;
//         unsigned short  tp_mac;
//         unsigned short  tp_net;
//         unsigned int    tp_sec;
//         unsigned int    tp_usec;
//};
func init() {
	_TP_LEN_START = _LONG_SIZE
	_TP_LEN_STOP = _TP_LEN_START + _INT_SIZE

	_TP_SNAPLEN_START = _TP_LEN_STOP
	_TP_SNAPLEN_STOP = _TP_SNAPLEN_START + _INT_SIZE

	_TP_MAC_START = _TP_SNAPLEN_STOP
	_TP_MAC_STOP = _TP_MAC_START + _SHORT_SIZE

	_TP_NET_START = _TP_MAC_STOP
	_TP_NET_STOP = _TP_NET_START + _SHORT_SIZE

	_TP_SEC_START = _TP_NET_STOP
	_TP_SEC_STOP = _TP_SEC_START + _INT_SIZE

	_TP_USEC_START = _TP_SEC_START
	_TP_USEC_STOP = _TP_USEC_START + _INT_SIZE

	_TX_START = _TP_USEC_STOP
	r := _TX_START % _TPACKET_ALIGNMENT
	if r > 0 {
		_TX_START += (_TPACKET_ALIGNMENT - r)
	}
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return fmt.Errorf("try again")
	case syscall.EINVAL:
		return fmt.Errorf("invalid argument")
	case syscall.ENOENT:
		return fmt.Errorf("no such file or directory")
	}
	return e
}

func copyFx(dst, src []byte, len uint64) {
	copy(dst, src[:len])
}

type Locker interface {
	Lock()
	Unlock()
}

type EmptyLock struct{}

func (l *EmptyLock) Lock()   {}
func (l *EmptyLock) Unlock() {}

type ZSocket struct {
	socket      int
	raw         []byte
	listening   int32
	frameNum    int
	frameSize   int
	rxEnabled   bool
	txEnabled   bool
	txChan      chan *ringFrame
	txFrameSize uint64
	txError     error
	rxFrames    []*ringFrame
	txFrames    []*ringFrame
}

func NewZSocket(ethIndex, options, blockNum int, ethType EthType) (*ZSocket, error) {
	zs := new(ZSocket)

	eT := hostToNetwork.htons(ethType[0:])
	// in Linux PF_PACKET is actually defined by AF_PACKET.
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(eT))
	if err != nil {
		return nil, err
	}
	zs.socket = sock
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = eT
	sll.Ifindex = ethIndex
	sll.Halen = _ETH_ALEN
	if err := syscall.Bind(sock, &sll); err != nil {
		return nil, err
	}

	zs.rxEnabled = options&ENABLE_RX == ENABLE_RX
	zs.txEnabled = options&ENABLE_TX == ENABLE_TX

	if err := syscall.SetsockoptInt(sock, syscall.SOL_PACKET, _PACKET_VERSION, _TPACKET_V1); err != nil {
		return nil, err
	}

	if blockNum <= 0 {
		blockNum = 256
	}
	req := &tpacketReq{}
	req.blockSize = uint(os.Getpagesize() << 2)
	req.frameSize = _TPACKET_ALIGNMENT << 7
	req.blockNum = uint(blockNum)
	req.frameNum = (req.blockSize / req.frameSize) * req.blockNum
	reqP := req.getPointer()
	if zs.rxEnabled {
		_, _, e1 := syscall.Syscall6(uintptr(syscall.SYS_SETSOCKOPT), uintptr(sock), uintptr(syscall.SOL_PACKET), uintptr(_PACKET_RX_RING), uintptr(reqP), uintptr(req.size()), 0)
		if e1 != 0 {
			return nil, errnoErr(e1)
		}
	}
	if zs.txEnabled {
		_, _, e1 := syscall.Syscall6(uintptr(syscall.SYS_SETSOCKOPT), uintptr(sock), uintptr(syscall.SOL_PACKET), uintptr(_PACKET_TX_RING), uintptr(reqP), uintptr(req.size()), 0)
		if e1 != 0 {
			return nil, errnoErr(e1)
		}
	}

	size := req.blockSize * req.blockNum
	if zs.txEnabled && zs.rxEnabled {
		size *= 2
	}

	bs, err := syscall.Mmap(sock, int64(0), int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_LOCKED|syscall.MAP_POPULATE)
	if err != nil {
		return nil, err
	}
	zs.raw = bs
	zs.frameNum = int(req.frameNum)
	zs.frameSize = int(req.frameSize)
	i := 0
	frLoc := 0
	if zs.rxEnabled {
		for i = 0; i < zs.frameNum; i++ {
			frLoc = i * zs.frameSize
			rf := &ringFrame{}
			rf.raw = zs.raw[frLoc : frLoc+zs.frameSize]
			zs.rxFrames = append(zs.rxFrames, rf)
		}
	}
	if zs.txEnabled {
		zs.txChan = make(chan *ringFrame, zs.frameNum)
		zs.txFrameSize = uint64(_TX_START + zs.frameSize)
		for t := 0; t < zs.frameNum; t, i = t+1, i+1 {
			frLoc = i * zs.frameSize
			tx := &ringFrame{}
			tx.raw = zs.raw[frLoc : frLoc+zs.frameSize]
			tx.txStart = tx.raw[_TX_START:]
			zs.txFrames = append(zs.txFrames, tx)
		}
		go zs.writeListener()
	} else {
		// this is an optimization for the write code so that it doesn't
		// have to check the boolean txEnabled
		zs.txError = fmt.Errorf("the TX ring is not enabled on this socket")
	}
	return zs, nil
}

func (zs *ZSocket) Listen(fx func(*Frame, uint64)) error {
	if !zs.rxEnabled {
		return fmt.Errorf("the RX ring is disabled on this socket")
	}
	if !atomic.CompareAndSwapInt32(&zs.listening, 0, 1) {
		return fmt.Errorf("there is already a listener on this socket")
	}
	pfd := &pollfd{}
	pfd.fd = zs.socket
	pfd.events = _POLLERR | _POLLIN
	pfd.revents = 0
	pfdP := uintptr(pfd.getPointer())

	rxIndex := 0
	rf := zs.rxFrames[rxIndex]
	for {
		for ; rf.rxReady(); rf = zs.rxFrames[rxIndex] {
			f := Frame(rf.raw[rf.macStart():])
			fx(&f, rf.tpLen())
			rf.rxSet()
			rxIndex = (rxIndex + 1) % zs.frameNum
		}
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, pfdP, uintptr(1), uintptr(1))
		if e1 != 0 {
			return e1
		}
	}
}

func (zs *ZSocket) Write(buf []byte, len uint64) error {
	return zs.WriteCopy(buf, len, copyFx)
}

func (zs *ZSocket) WriteCopy(buf []byte, len uint64, copyFx func(dst, srcf []byte, len uint64)) error {
	if zs.txError != nil {
		return zs.txError
	}
	if len > zs.txFrameSize {
		return fmt.Errorf("the length of the write exceeds the size of the TX frame")
	}
	tx := <-zs.txChan
	tx.setTpLen(len)
	tx.setTpSnapLen(len)
	copyFx(tx.txStart, buf, len)
	tx.txSet()
	return nil
}

func (zs *ZSocket) writeListener() {
	pfd := &pollfd{}
	pfd.fd = zs.socket
	pfd.events = _POLLERR | _POLLOUT
	pfd.revents = 0
	pfdP := uintptr(pfd.getPointer())

	txIndex := 0
	rf := zs.txFrames[txIndex]
	for {
		for ; rf.txReady(); rf = zs.txFrames[txIndex] {
			zs.txChan <- rf
			txIndex = (txIndex + 1) % zs.frameNum
		}
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, pfdP, uintptr(1), uintptr(1))
		if e1 != 0 {
			zs.txError = e1
			return
		}
	}
}

type tpacketReq struct {
	blockSize, /* Minimal size of contiguous block */
	blockNum, /* Number of blocks */
	frameSize, /* Size of frame */
	frameNum uint
}

func (tr *tpacketReq) getPointer() unsafe.Pointer {
	if _INT_SIZE == 4 {
		return unsafe.Pointer(&(struct {
			blockSize,
			blockNum,
			frameSize,
			frameNum uint32
		}{
			uint32(tr.blockSize),
			uint32(tr.blockNum),
			uint32(tr.frameSize),
			uint32(tr.frameNum),
		}))
	} else {
		return unsafe.Pointer(&(struct {
			blockSize,
			blockNum,
			frameSize,
			frameNum uint64
		}{
			uint64(tr.blockSize),
			uint64(tr.blockNum),
			uint64(tr.frameSize),
			uint64(tr.frameNum),
		}))
	}
}

func (req *tpacketReq) size() int {
	return _INT_SIZE * 4
}

type pollfd struct {
	fd      int
	events  int16
	revents int16
}

func (pfd *pollfd) getPointer() unsafe.Pointer {
	if _INT_SIZE == 4 {
		return unsafe.Pointer(&(struct {
			fd      int32
			events  int16
			revents int16
		}{
			int32(pfd.fd),
			pfd.events,
			pfd.revents,
		}))
	} else {
		return unsafe.Pointer(&(struct {
			fd      int64
			events  int16
			revents int16
		}{
			int64(pfd.fd),
			pfd.events,
			pfd.revents,
		}))
	}
}

func (req *pollfd) size() int {
	return _INT_SIZE + 2*_SHORT_SIZE
}

type ringFrame struct {
	raw     []byte
	txStart []byte
}

func (rf *ringFrame) rxReady() bool {
	return host.long(rf.raw[0:_LONG_SIZE])&_TP_STATUS_USER == _TP_STATUS_USER
}

func (rf *ringFrame) macStart() uint16 {
	return host.short(rf.raw[_TP_MAC_START:_TP_MAC_STOP])
}

func (rf *ringFrame) tpLen() uint64 {
	return host.int(rf.raw[_TP_LEN_START:_TP_LEN_STOP])
}

func (rf *ringFrame) setTpLen(v uint64) {
	host.putInt(rf.raw[_TP_LEN_START:_TP_LEN_STOP], v)
}

func (rf *ringFrame) setTpSnapLen(v uint64) {
	host.putInt(rf.raw[_TP_SNAPLEN_START:_TP_SNAPLEN_STOP], v)
}

func (rf *ringFrame) rxSet() {
	host.putLong(rf.raw[0:_LONG_SIZE], uint64(_TP_STATUS_KERNEL))
	// we don't need a memory barrier because
}

func (rf *ringFrame) txReady() bool {
	return host.long(rf.raw[0:_LONG_SIZE])&(_TP_STATUS_SEND_REQUEST|_TP_STATUS_SENDING) == 0
}

func (rf *ringFrame) txSet() {
	host.putLong(rf.raw[0:_LONG_SIZE], uint64(_TP_STATUS_SEND_REQUEST))
	// we may need a memory barrier in the future
}
