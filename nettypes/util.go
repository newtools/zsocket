package nettypes

type EthPacket interface {
	EthType() EthType
	Bytes() []byte
}

type IPPacket interface {
	IPProtocol() IPProtocol
	Bytes() []byte
}

func padLeft(str, pad string, length int) string {
	for ; length > 0; length-- {
		str = pad + str
	}
	return str
}
