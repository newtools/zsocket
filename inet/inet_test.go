package inet

import "testing"

func byteEqual(v1, v2 []byte) bool {
	v1l := len(v1)
	v2l := len(v2)
	if v1l != v2l {
		return false
	}
	for i := 0; i < v1l; i++ {
		if v1[i] != v2[i] {
			return false
		}
	}
	return true
}

func TestShort(t *testing.T) {
	i := Short([]byte{0x0, 0x1})
	if IsBigEndian && i != 1 {
		t.Errorf("wrong value: %v", i)
	} else if IsLittleEndian && i != 256 {
		t.Errorf("wrong value: %v", i)
	}
}

func TestPutShort(t *testing.T) {
	dst := make([]byte, 2)
	PutShort(dst, uint16(256))
	if IsBigEndian && !byteEqual(dst, []byte{0x1, 0x0}) {
		t.Errorf("wrong value: %v", dst)
	} else if IsLittleEndian && !byteEqual(dst, []byte{0x0, 0x1}) {
		t.Errorf("wrong value: %v", dst)
	}
}

func TestInt(t *testing.T) {
	var bs []byte
	if HOST_INT_SIZE == 4 {
		bs = []byte{0x0, 0x0, 0x0, 0x1}
		i := Int(bs)
		if IsBigEndian && i != 1 {
			t.Errorf("wrong value: %v", i)
		} else if IsLittleEndian && i != 16777216 {
			t.Errorf("wrong value: %v", i)
		}
	} else {
		if IsBigEndian {
			bs = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
			i := Int(bs)
			if i != 1 {
				t.Errorf("wrong value: %v", i)
			}
		} else {
			bs = []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
			i := Int(bs)
			if i != 1 {
				t.Errorf("wrong value: %v", i)
			}
		}

	}
}

func TestPutInt(t *testing.T) {
	var dst []byte
	if HOST_INT_SIZE == 4 {
		dst = make([]byte, 4)
		PutInt(dst, uint32(1))
		if IsBigEndian && !byteEqual(dst, []byte{0x0, 0x0, 0x0, 0x1}) {
			t.Errorf("wrong value: %v", dst)
		} else if IsLittleEndian && !byteEqual(dst, []byte{0x1, 0x0, 0x0, 0x0}) {
			t.Errorf("wrong value: %v", dst)
		}
	} else {
		dst = make([]byte, 8)
		PutInt(dst, uint32(1))
		if IsBigEndian && !byteEqual(dst, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}) {
			t.Errorf("wrong value: %v", dst)
		} else if IsLittleEndian && !byteEqual(dst, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}) {
			t.Errorf("wrong value: %v", dst)
		}
	}
}

func TestLong(t *testing.T) {
	var bs []byte
	if HOST_LONG_SIZE == 4 {
		bs = []byte{0x0, 0x0, 0x0, 0x1}
		i := Long(bs)
		if IsBigEndian && i != 1 {
			t.Errorf("wrong value: %v", i)
		} else if IsLittleEndian && i != 16777216 {
			t.Errorf("wrong value: %v", i)
		}
	} else {
		if IsBigEndian {
			bs = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
			i := Long(bs)
			if i != 1 {
				t.Errorf("wrong value: %v", i)
			}
		} else {
			bs = []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
			i := Long(bs)
			if i != 1 {
				t.Errorf("wrong value: %v", i)
			}
		}

	}
}

func TestPutLong(t *testing.T) {
	var dst []byte
	if HOST_LONG_SIZE == 4 {
		dst = make([]byte, 4)
		PutLong(dst, uint64(1))
		if IsBigEndian && !byteEqual(dst, []byte{0x0, 0x0, 0x0, 0x1}) {
			t.Errorf("wrong value: %v", dst)
		} else if IsLittleEndian && !byteEqual(dst, []byte{0x1, 0x0, 0x0, 0x0}) {
			t.Errorf("wrong value: %v", dst)
		}
	} else {
		dst = make([]byte, 8)
		PutLong(dst, uint64(1))
		if IsBigEndian && !byteEqual(dst, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}) {
			t.Errorf("wrong value: %v", dst)
		} else if IsLittleEndian && !byteEqual(dst, []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}) {
			t.Errorf("wrong value: %v", dst)
		}
	}
}

func TestHToNS(t *testing.T) {
	i := HToNS([]byte{0x0, 0x1})
	if IsBigEndian && i != 1 {
		t.Errorf("wrong value: %v", i)
	} else if IsLittleEndian && i != 256 {
		t.Errorf("wrong value: %v", i)
	}
}

func TestHToNSFS(t *testing.T) {
	i := HToNSFS(1)
	if IsBigEndian && i != 1 {
		t.Errorf("wrong value: %v", i)
	} else if IsLittleEndian && i != 256 {
		t.Errorf("wrong value: %v", i)
	}
}

func TestPutHToNS(t *testing.T) {
	dst := make([]byte, 2)
	PutHToNS(dst, 1)
	if !byteEqual(dst, []byte{0x0, 0x1}) {
		t.Errorf("wrong value: %v", dst)
	}
}

func TestNToHS(t *testing.T) {
	i := NToHS([]byte{0x0, 0x1})
	if IsBigEndian && i != 1 {
		t.Errorf("wrong value: %v", i)
	} else if IsLittleEndian && i != 1 {
		t.Errorf("wrong value: %v", i)
	}
}

func TestPutNToHS(t *testing.T) {
	dst := make([]byte, 2)
	PutNToHS(dst, 1)
	if IsBigEndian && !byteEqual(dst, []byte{0x0, 0x1}) {
		t.Errorf("wrong value: %v", dst)
	} else if IsLittleEndian && !byteEqual(dst, []byte{0x1, 0x0}) {
		t.Errorf("wrong value: %v", dst)
	}
}
