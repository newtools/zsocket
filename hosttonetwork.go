package zsocket

//#define LONG_SIZE sizeof(long)
//#define INT_SIZE sizeof(int)
//#define SHORT_SIZE sizeof(short)
//#define CHAR_SIZE sizeof(char)
import "C"
import "encoding/binary"

const (
	_LONG_SIZE  = C.LONG_SIZE
	_INT_SIZE   = C.INT_SIZE
	_SHORT_SIZE = C.SHORT_SIZE
	_CHAR_SIZE  = C.CHAR_SIZE
)

var hostToNetwork shton
var host shost

type shton struct {
	htonShortConv
	htonIntConv
}

type shost struct {
	hostLongConv
	hostShortConv
	hostIntConv
}

type hostLongConv interface {
	long([]byte) uint64
	putLong([]byte, uint64)
}

type hostShortConv interface {
	short([]byte) uint16
}

type hostIntConv interface {
	int([]byte) int
	putInt([]byte, int)
}

type htonShortConv interface {
	ntohs([]byte) uint16
	putntohs([]byte, uint16)
	htons([]byte) uint16
	puthtons([]byte, uint16)
}

type htonIntConv interface {
	ntohi([]byte) uint32
}

func init() {
	// in the future lets account for architectures
	// that are big endian
	host = shost{}
	hostToNetwork = shton{}
	if _INT_SIZE == 4 {
		host.hostIntConv = &leInt32Conv{}
	} else {
		host.hostIntConv = &leInt64Conv{}
	}
	if _LONG_SIZE == 4 {
		host.hostLongConv = &leLong32Conv{}
	} else {
		host.hostLongConv = &leLong64Conv{}
	}
	host.hostShortConv = &leShortConv{}
	hostToNetwork.htonIntConv = &leInt32HtonConv{}
	hostToNetwork.htonShortConv = &leShortHtonConv{}
}

type leLong32Conv struct{}

/* this is host to host */
func (l *leLong32Conv) long(b []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(b))
}

func (l *leLong32Conv) putLong(b []byte, t uint64) {
	v := uint32(t)
	binary.LittleEndian.PutUint32(b, v)
}

type leLong64Conv struct{}

/* this is host to host */
func (l *leLong64Conv) long(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

func (l *leLong64Conv) putLong(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

type leShortConv struct{}

func (l *leShortConv) short(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

type leInt32Conv struct{}

func (l *leInt32Conv) int(b []byte) int {
	return int(binary.LittleEndian.Uint32(b))
}

func (l *leInt32Conv) putInt(b []byte, v int) {
	binary.LittleEndian.PutUint32(b, uint32(v))
}

type leInt64Conv struct{}

func (l *leInt64Conv) int(b []byte) int {
	return int(binary.LittleEndian.Uint64(b))
}

func (l *leInt64Conv) putInt(b []byte, v int) {
	binary.LittleEndian.PutUint64(b, uint64(v))
}

type leShortHtonConv struct{}

func (l *leShortHtonConv) ntohs(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func (l *leShortHtonConv) putntohs(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

func (l *leShortHtonConv) htons(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

func (l *leShortHtonConv) puthtons(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
}

type leInt32HtonConv struct{}

func (l *leInt32HtonConv) ntohi(b []byte) uint32 {
	// return uint32(b[0])>>24 |
	// 	uint32(b[1])>>8 |
	// 	uint32(b[2])<<8 |
	// 	uint32(b[3])<<24
	return binary.BigEndian.Uint32(b)
}
