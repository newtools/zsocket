package nettypes

type EthPacket interface {
	EthType() EthType
}

type IPPacket interface {
	IPProtocol() IPProtocol
}

func padLeft(str, pad string, length int) string {
	for ; length > 0; length-- {
		str = pad + str
	}
	return str
}
