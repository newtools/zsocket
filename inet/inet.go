package inet

import (
	"encoding/binary"
	"unsafe"
)

var (
	IsBigEndian    bool
	IsLittleEndian bool
	HostByteOrder  binary.ByteOrder
	// host to host
	Short    func([]byte) uint16
	PutShort func([]byte, uint16)
	Int      func([]byte) uint32
	PutInt   func([]byte, uint32)
	Long     func([]byte) uint64
	PutLong  func([]byte, uint64)

	// (nh)s
	NToHS    func([]byte) uint16
	PutNToHS func([]byte, uint16)
	HToNS    func([]byte) uint16
	HToNSFS  func(uint16) uint16
	PutHToNS func([]byte, uint16)

	// (nh)i
	NToHI    func([]byte) uint32
	PutNToHI func([]byte, uint32)
	HToNI    func([]byte) uint32
	HToNIFI  func(uint32) uint32
	PutHToNI func([]byte, uint32)

	// (nh)l
	NToHL    func([]byte) uint64
	PutNToHL func([]byte, uint64)
	HToNL    func([]byte) uint64
	HToNLFL  func(uint64) uint64
	PutHToNL func([]byte, uint64)
)

func init() {
	isBE := bigEndian()
	if isBE {
		IsBigEndian = true
		IsLittleEndian = false
		HostByteOrder = binary.BigEndian
	} else {
		IsBigEndian = false
		IsLittleEndian = true
		HostByteOrder = binary.LittleEndian
	}
	Short = HostByteOrder.Uint16
	PutShort = HostByteOrder.PutUint16

	PutHToNS = binary.BigEndian.PutUint16
	HToNS = HostByteOrder.Uint16
	PutNToHS = HostByteOrder.PutUint16
	NToHS = binary.BigEndian.Uint16
	if isBE {
		HToNSFS = _beSFS
		HToNIFI = _beIFI
		HToNLFL = _beLFL
	} else {
		HToNSFS = _beToLeSFS
		HToNLFL = _beToLeLFL
		HToNIFI = _beToLeIFI
	}
	if HOST_INT_SIZE == 4 {
		Int = HostByteOrder.Uint32
		PutInt = HostByteOrder.PutUint32

		PutHToNI = binary.BigEndian.PutUint32
		HToNI = HostByteOrder.Uint32
		PutNToHI = HostByteOrder.PutUint32
		NToHI = binary.BigEndian.Uint32
	} else {
		Int = func(b []byte) uint32 {
			return uint32(HostByteOrder.Uint64(b))
		}
		PutInt = func(b []byte, v uint32) {
			HostByteOrder.PutUint64(b, uint64(v))
		}
		PutHToNI = func(b []byte, v uint32) {
			binary.BigEndian.PutUint64(b, uint64(v))
		}
		HToNI = func(b []byte) uint32 {
			return uint32(HostByteOrder.Uint64(b))
		}
		PutNToHI = func(b []byte, v uint32) {
			HostByteOrder.PutUint64(b, uint64(v))
		}
		NToHI = func(b []byte) uint32 {
			return uint32(binary.BigEndian.Uint64(b))
		}
	}
	if HOST_LONG_SIZE == 4 {
		Long = func(b []byte) uint64 {
			return uint64(HostByteOrder.Uint32(b))
		}
		PutLong = func(b []byte, v uint64) {
			HostByteOrder.PutUint32(b, uint32(v))
		}
		PutHToNL = func(b []byte, v uint64) {
			binary.BigEndian.PutUint32(b, uint32(v))
		}
		HToNL = func(b []byte) uint64 {
			return uint64(HostByteOrder.Uint32(b))
		}
		PutNToHL = func(b []byte, v uint64) {
			HostByteOrder.PutUint32(b, uint32(v))
		}
		NToHL = func(b []byte) uint64 {
			return uint64(binary.BigEndian.Uint32(b))
		}
	} else {
		Long = HostByteOrder.Uint64
		PutLong = HostByteOrder.PutUint64
		PutHToNL = binary.BigEndian.PutUint64
		HToNL = HostByteOrder.Uint64
		PutNToHL = HostByteOrder.PutUint64
		NToHL = binary.BigEndian.Uint64
	}

}

func bigEndian() (ret bool) {
	var i int = 0x1
	bs := (*[int(unsafe.Sizeof(0))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0

}

func _beSFS(v uint16) uint16 {
	return v
}

func _beIFI(v uint32) uint32 {
	return v
}

func _beLFL(v uint64) uint64 {
	return v
}

func _beToLeSFS(v uint16) uint16 {
	return (v&0xff)<<8 |
		(v&0xff00)>>8
}

func _beToLeIFI(v uint32) uint32 {
	return (v&0xff)<<24 |
		(v&0xff00)<<8 |
		(v&0xff0000)>>8 |
		(v&0xff000000)>>24
}

func _beToLeLFL(v uint64) uint64 {
	return (v&0xff)<<56 |
		(v&0xff00)<<40 |
		(v&0xff0000)<<24 |
		(v&0xff000000)<<8 |
		(v&0xff00000000)>>8 |
		(v&0xff0000000000)>>24 |
		(v&0xff000000000000)>>40 |
		(v&0xff00000000000000)>>56
}
