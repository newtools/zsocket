package zsocket

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/newtools/zsocket/inet"
	"github.com/newtools/zsocket/nettypes"
)

const (
	TPACKET_ALIGNMENT = 16

	MINIMUM_FRAME_SIZE = TPACKET_ALIGNMENT << 7
	MAXIMUM_FRAME_SIZE = TPACKET_ALIGNMENT << 11

	ENABLE_RX       = 1 << 0
	ENABLE_TX       = 1 << 1
	DISABLE_TX_LOSS = 1 << 2
)

const (
	_ETH_ALEN = 6

	_PACKET_VERSION = 0xa
	_PACKET_RX_RING = 0x5
	_PACKET_TX_RING = 0xd
	_PACKET_LOSS    = 0xe

	_TPACKET_V1 = 0
	/* rx status */
	_TP_STATUS_KERNEL          = 0
	_TP_STATUS_USER            = 1 << 0
	_TP_STATUS_COPY            = 1 << 1
	_TP_STATUS_LOSING          = 1 << 2
	_TP_STATUS_CSUMNOTREADY    = 1 << 3
	_TP_STATUS_VLAN_VALID      = 1 << 4 /* auxdata has valid tp_vlan_tci */
	_TP_STATUS_BLK_TMO         = 1 << 5
	_TP_STATUS_VLAN_TPID_VALID = 1 << 6 /* auxdata has valid tp_vlan_tpid */
	_TP_STATUS_CSUM_VALID      = 1 << 7
	/* tx status */
	_TP_STATUS_AVAILABLE    = 0
	_TP_STATUS_SEND_REQUEST = 1 << 0
	_TP_STATUS_SENDING      = 1 << 1
	_TP_STATUS_WRONG_FORMAT = 1 << 2
	/* tx and rx status */
	_TP_STATUS_TS_SOFTWARE     = 1 << 29
	_TP_STATUS_TS_RAW_HARDWARE = 1 << 31
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
	_TP_LEN_START = inet.HOST_LONG_SIZE
	_TP_LEN_STOP = _TP_LEN_START + inet.HOST_INT_SIZE

	_TP_SNAPLEN_START = _TP_LEN_STOP
	_TP_SNAPLEN_STOP = _TP_SNAPLEN_START + inet.HOST_INT_SIZE

	_TP_MAC_START = _TP_SNAPLEN_STOP
	_TP_MAC_STOP = _TP_MAC_START + inet.HOST_SHORT_SIZE

	_TX_START = _TP_MAC_STOP + inet.HOST_SHORT_SIZE + inet.HOST_INT_SIZE + inet.HOST_INT_SIZE
	r := _TX_START % TPACKET_ALIGNMENT
	if r > 0 {
		_TX_START += (TPACKET_ALIGNMENT - r)
	}
}

func PacketOffset() int {
	return _TX_START
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

func copyFx(dst, src []byte, len uint16) uint16 {
	copy(dst, src)
	return len
}

// IZSocket is an interface for interacting with eth-iface like
// objects in the ZSocket code-base. This has basically
// simply enabled the FakeInterface code to work.
type IZSocket interface {
	MaxPackets() int32
	MaxPacketSize() uint16
	WrittenPackets() int32
	Listen(fx func(*nettypes.Frame, uint16, uint16))
	WriteToBuffer(buf []byte, l uint16) (int32, error)
	CopyToBuffer(buf []byte, l uint16, copyFx func(dst, src []byte, l uint16)) (int32, error)
	FlushFrames() (uint, error, []error)
	Close() error
}

// ZSocket opens a zero copy ring-buffer to the specified interface.
// Do not manually initialize ZSocket. Use `NewZSocket`.
type ZSocket struct {
	socket         int
	raw            []byte
	listening      int32
	frameNum       int32
	frameSize      uint16
	rxEnabled      bool
	rxFrames       []*ringFrame
	txEnabled      bool
	txLossDisabled bool
	txFrameSize    uint16
	txIndex        int32
	txWritten      int32
	txWrittenIndex int32
	txFrames       []*ringFrame
}

// NewZSocket opens a "ZSocket" on the specificed interface
// (by interfaceIndex). Whether the TX ring, RX ring, or both
// are enabled are options that can be passed. Additionally,
// an option can be passed that will tell the kernel to pay
// attention to packet faults, called DISABLE_TX_LOSS.
func NewZSocket(ethIndex, options int, maxFrameSize, maxTotalFrames uint, ethType nettypes.EthType) (*ZSocket, error) {
	if maxFrameSize < MINIMUM_FRAME_SIZE ||
		maxFrameSize > MAXIMUM_FRAME_SIZE ||
		(maxFrameSize&(maxFrameSize-1)) > 0 {
		return nil, fmt.Errorf("maxFrameSize must be at least %d (MINIMUM_FRAME_SIZE), be at most %d (MAXIMUM_FRAME_SIZE), and be a power of 2",
			MINIMUM_FRAME_SIZE, MAXIMUM_FRAME_SIZE)
	}
	if maxTotalFrames < 16 && maxTotalFrames%8 == 0 {
		return nil, fmt.Errorf("maxTotalFrames must be at least 16, and be a multiple of 8")
	}

	zs := new(ZSocket)
	eT := inet.HToNS(ethType[0:])
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
	zs.txLossDisabled = options&DISABLE_TX_LOSS == DISABLE_TX_LOSS

	if err := syscall.SetsockoptInt(sock, syscall.SOL_PACKET, _PACKET_VERSION, _TPACKET_V1); err != nil {
		return nil, err
	}

	req := &tpacketReq{}
	pageSize := uint(os.Getpagesize())
	var frameSize uint
	if maxFrameSize < pageSize {
		frameSize = calculateLargestFrame(maxFrameSize)
	} else {
		frameSize = (maxFrameSize / pageSize) * pageSize
	}
	req.frameSize = frameSize
	req.blockSize = req.frameSize * 8
	req.blockNum = maxTotalFrames / 8
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
		/*
			Can't get this to work for some reason
			if !zs.txLossDisabled {
				if err := syscall.SetsockoptInt(sock, syscall.SOL_PACKET, _PACKET_LOSS, 1); err != nil {
					return nil, err
				}
			}*/
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
	zs.frameNum = int32(req.frameNum)
	zs.frameSize = uint16(req.frameSize)
	i := 0
	frLoc := 0
	if zs.rxEnabled {
		for i = 0; i < int(zs.frameNum); i++ {
			frLoc = i * int(zs.frameSize)
			rf := &ringFrame{}
			rf.raw = zs.raw[frLoc : frLoc+int(zs.frameSize)]
			zs.rxFrames = append(zs.rxFrames, rf)
		}
	}
	if zs.txEnabled {
		zs.txFrameSize = zs.frameSize - uint16(_TX_START)
		zs.txWritten = 0
		zs.txWrittenIndex = -1
		for t := 0; t < int(zs.frameNum); t, i = t+1, i+1 {
			frLoc = i * int(zs.frameSize)
			tx := &ringFrame{}
			tx.raw = zs.raw[frLoc : frLoc+int(zs.frameSize)]
			tx.txStart = tx.raw[_TX_START:]
			zs.txFrames = append(zs.txFrames, tx)
		}
	}
	return zs, nil
}

func calculateLargestFrame(ceil uint) uint {
	i := uint(MINIMUM_FRAME_SIZE)
	for i < ceil {
		i <<= 1
	}
	return (i >> 1)
}

// Returns the maximum amount of frame packets that can be written
func (zs *ZSocket) MaxPackets() int32 {
	return zs.frameNum
}

// Returns the frame size in bytes
func (zs *ZSocket) MaxPacketSize() uint16 {
	return zs.txFrameSize
}

// Returns the amount of packets, written to the tx ring, that
// haven't been flushed.
func (zs *ZSocket) WrittenPackets() int32 {
	return atomic.LoadInt32(&zs.txWritten)
}

// Listen to all specified packets in the RX ring-buffer
func (zs *ZSocket) Listen(fx func(*nettypes.Frame, uint16, uint16)) error {
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
	rxIndex := int32(0)
	rf := zs.rxFrames[rxIndex]
	pollTimeout := -1
	pTOPointer := uintptr(unsafe.Pointer(&pollTimeout))
	for {
		for ; rf.rxReady(); rf = zs.rxFrames[rxIndex] {
			f := nettypes.Frame(rf.raw[rf.macStart():])
			fx(&f, rf.tpLen(), rf.tpSnapLen())
			rf.rxSet()
			rxIndex = (rxIndex + 1) % zs.frameNum
		}
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, pfdP, uintptr(1), pTOPointer)
		if e1 != 0 {
			return e1
		}
	}
}

// WriteToBuffer writes a raw frame in bytes to the TX ring buffer.
// The length of the frame must be specified.
func (zs *ZSocket) WriteToBuffer(buf []byte, l uint16) (int32, error) {
	if l > zs.txFrameSize {
		return -1, fmt.Errorf("the length of the write exceeds the size of the TX frame")
	}
	if l < 0 {
		return zs.CopyToBuffer(buf, uint16(len(buf)), copyFx)
	}
	return zs.CopyToBuffer(buf[:l], l, copyFx)
}

// CopyToBuffer is like WriteToBuffer, it writes a frame to the TX
// ring buffer. However, it can take a function argument, that will
// be passed the raw TX byes so that custom logic can be applied
// to copying the frame (for example, encrypting the frame).
func (zs *ZSocket) CopyToBuffer(buf []byte, l uint16, copyFx func(dst, src []byte, l uint16) uint16) (int32, error) {
	if !zs.txEnabled {
		return -1, fmt.Errorf("the TX ring is not enabled on this socket")
	}
	tx, txIndex, err := zs.getFreeTx()
	if err != nil {
		return -1, err
	}
	cL := copyFx(tx.txStart, buf, l)
	tx.setTpLen(cL)
	tx.setTpSnapLen(cL)
	written := atomic.AddInt32(&zs.txWritten, 1)
	if written == 1 {
		atomic.SwapInt32(&zs.txWrittenIndex, txIndex)
	}
	return txIndex, nil
}

// FlushFrames tells the kernel to flush all packets written
// to the TX ring buffer.n
func (zs *ZSocket) FlushFrames() (uint, error, []error) {
	if !zs.txEnabled {
		return 0, fmt.Errorf("the TX ring is not enabled on this socket, there is nothing to flush"), nil
	}
	var index int32
	for {
		index = atomic.LoadInt32(&zs.txWrittenIndex)
		if index == -1 {
			return 0, nil, nil
		}
		if atomic.CompareAndSwapInt32(&zs.txWrittenIndex, index, -1) {
			break
		}
	}
	written := atomic.SwapInt32(&zs.txWritten, 0)
	framesFlushed := uint(0)
	frameNum := int32(zs.frameNum)
	z := uintptr(0)
	for t, w := index, written; w > 0; w-- {
		zs.txFrames[t].txSet()
		t = (t + 1) % frameNum
	}
	if _, _, e1 := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(zs.socket), z, z, z, z, z); e1 != 0 {
		return framesFlushed, e1, nil
	}
	var errs []error = nil
	for t, w := index, written; w > 0; w-- {
		tx := zs.txFrames[t]
		if zs.txLossDisabled && tx.txWrongFormat() {
			errs = append(errs, txIndexError(t))
		} else {
			framesFlushed++
		}
		tx.txSetMB()
		t = (t + 1) % frameNum
	}
	return framesFlushed, nil, errs
}

// Close socket
func (zs *ZSocket) Close() error {
	return syscall.Close(zs.socket)
}

func (zs *ZSocket) getFreeTx() (*ringFrame, int32, error) {
	if atomic.LoadInt32(&zs.txWritten) == zs.frameNum {
		return nil, -1, fmt.Errorf("the tx ring buffer is full")
	}
	var txIndex int32
	for txIndex = atomic.LoadInt32(&zs.txIndex); !atomic.CompareAndSwapInt32(&zs.txIndex, txIndex, (txIndex+1)%int32(zs.frameNum)); txIndex = atomic.LoadInt32(&zs.txIndex) {
	}
	tx := zs.txFrames[txIndex]
	for !tx.txReady() {
		pfd := &pollfd{}
		pfd.fd = zs.socket
		pfd.events = _POLLERR | _POLLOUT
		pfd.revents = 0
		timeout := -1
		_, _, e1 := syscall.Syscall(syscall.SYS_POLL, uintptr(pfd.getPointer()), uintptr(1), uintptr(unsafe.Pointer(&timeout)))
		if e1 != 0 {
			return nil, -1, e1
		}
	}
	for !tx.txMBReady() {
		runtime.Gosched()
	}
	return tx, txIndex, nil
}

type txIndexError int32

func (ie txIndexError) Error() string {
	return fmt.Sprintf("bad format in tx frame %d", ie)
}

type tpacketReq struct {
	blockSize, /* Minimal size of contiguous block */
	blockNum, /* Number of blocks */
	frameSize, /* Size of frame */
	frameNum uint
}

func (tr *tpacketReq) getPointer() unsafe.Pointer {
	if inet.HOST_INT_SIZE == 4 {
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
	return inet.HOST_INT_SIZE * 4
}

type pollfd struct {
	fd      int
	events  int16
	revents int16
}

func (pfd *pollfd) getPointer() unsafe.Pointer {
	if inet.HOST_INT_SIZE == 4 {
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
	return inet.HOST_INT_SIZE + 2*inet.HOST_SHORT_SIZE
}

type ringFrame struct {
	raw     []byte
	txStart []byte
	mb      uint32
}

func (rf *ringFrame) macStart() uint16 {
	return inet.Short(rf.raw[_TP_MAC_START:_TP_MAC_STOP])
}

func (rf *ringFrame) tpLen() uint16 {
	return uint16(inet.Int(rf.raw[_TP_LEN_START:_TP_LEN_STOP]))
}

func (rf *ringFrame) setTpLen(v uint16) {
	inet.PutInt(rf.raw[_TP_LEN_START:_TP_LEN_STOP], uint32(v))
}

func (rf *ringFrame) tpSnapLen() uint16 {
	return uint16(inet.Int(rf.raw[_TP_SNAPLEN_START:_TP_SNAPLEN_STOP]))
}

func (rf *ringFrame) setTpSnapLen(v uint16) {
	inet.PutInt(rf.raw[_TP_SNAPLEN_START:_TP_SNAPLEN_STOP], uint32(v))
}

func (rf *ringFrame) rxReady() bool {
	return inet.Long(rf.raw[0:inet.HOST_LONG_SIZE])&_TP_STATUS_USER == _TP_STATUS_USER && atomic.CompareAndSwapUint32(&rf.mb, 0, 1)
}

func (rf *ringFrame) rxSet() {
	inet.PutLong(rf.raw[0:inet.HOST_LONG_SIZE], uint64(_TP_STATUS_KERNEL))
	// this acts as a memory barrier
	atomic.StoreUint32(&rf.mb, 0)
}

func (rf *ringFrame) txWrongFormat() bool {
	return inet.Long(rf.raw[0:inet.HOST_LONG_SIZE])&_TP_STATUS_WRONG_FORMAT == _TP_STATUS_WRONG_FORMAT
}

func (rf *ringFrame) txReady() bool {
	return inet.Long(rf.raw[0:inet.HOST_LONG_SIZE])&(_TP_STATUS_SEND_REQUEST|_TP_STATUS_SENDING) == 0
}

func (rf *ringFrame) txMBReady() bool {
	return atomic.CompareAndSwapUint32(&rf.mb, 0, 1)
}

func (rf *ringFrame) txSet() {
	inet.PutLong(rf.raw[0:inet.HOST_LONG_SIZE], uint64(_TP_STATUS_SEND_REQUEST))
}

func (rf *ringFrame) txSetMB() {
	atomic.StoreUint32(&rf.mb, 0)
}

func (rf *ringFrame) printRxStatus() {
	s := inet.Long(rf.raw[0:inet.HOST_LONG_SIZE])
	fmt.Printf("RX STATUS :")
	if s == 0 {
		fmt.Printf(" Kernel")
	}
	if _TP_STATUS_USER&s > 0 {
		fmt.Printf(" User")
	}
	if _TP_STATUS_COPY&s > 0 {
		fmt.Printf(" Copy")
	}
	if _TP_STATUS_LOSING&s > 0 {
		fmt.Printf(" Losing")
	}
	if _TP_STATUS_CSUMNOTREADY&s > 0 {
		fmt.Printf(" CSUM-NotReady")
	}
	if _TP_STATUS_VLAN_VALID&s > 0 {
		fmt.Printf(" VlanValid")
	}
	if _TP_STATUS_BLK_TMO&s > 0 {
		fmt.Printf(" BlkTMO")
	}
	if _TP_STATUS_VLAN_TPID_VALID&s > 0 {
		fmt.Printf(" VlanTPIDValid")
	}
	if _TP_STATUS_CSUM_VALID&s > 0 {
		fmt.Printf(" CSUM-Valid")
	}
	rf.printRxTxStatus(s)
	fmt.Printf("\n")
}

func (rf *ringFrame) printTxStatus() {
	s := inet.Long(rf.raw[0:inet.HOST_LONG_SIZE])
	fmt.Printf("TX STATUS :")
	if s == 0 {
		fmt.Printf(" Available")
	}
	if s&_TP_STATUS_SEND_REQUEST > 0 {
		fmt.Printf(" SendRequest")
	}
	if s&_TP_STATUS_SENDING > 0 {
		fmt.Printf(" Sending")
	}
	if s&_TP_STATUS_WRONG_FORMAT > 0 {
		fmt.Printf(" WrongFormat")
	}
	rf.printRxTxStatus(s)
	fmt.Printf("\n")
}

func (rf *ringFrame) printRxTxStatus(s uint64) {
	if s&_TP_STATUS_TS_SOFTWARE > 0 {
		fmt.Printf(" Software")
	}
	if s&_TP_STATUS_TS_RAW_HARDWARE > 0 {
		fmt.Printf(" Hardware")
	}
}
