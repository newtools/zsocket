package zsocket

type EthType [2]byte

var (
	All                 = EthType{0x00, 0x03}
	IPv4                = EthType{0x08, 0x00}
	ARP                 = EthType{0x08, 0x06}
	WakeOnLAN           = EthType{0x08, 0x42}
	TRILL               = EthType{0x22, 0xF3}
	DECnetPhase4        = EthType{0x60, 0x03}
	RARP                = EthType{0x80, 0x35}
	AppleTalk           = EthType{0x80, 0x9B}
	AARP                = EthType{0x80, 0xF3}
	IPX1                = EthType{0x81, 0x37}
	IPX2                = EthType{0x81, 0x38}
	QNXQnet             = EthType{0x82, 0x04}
	IPv6                = EthType{0x86, 0xDD}
	EthernetFlowControl = EthType{0x88, 0x08}
	IEEE802_3           = EthType{0x88, 0x09}
	CobraNet            = EthType{0x88, 0x19}
	MPLSUnicast         = EthType{0x88, 0x47}
	MPLSMulticast       = EthType{0x88, 0x48}
	PPPoEDiscovery      = EthType{0x88, 0x63}
	PPPoESession        = EthType{0x88, 0x64}
	JumboFrames         = EthType{0x88, 0x70}
	HomePlug1_0MME      = EthType{0x88, 0x7B}
	IEEE802_1X          = EthType{0x88, 0x8E}
	PROFINET            = EthType{0x88, 0x92}
	HyperSCSI           = EthType{0x88, 0x9A}
	AoE                 = EthType{0x88, 0xA2}
	EtherCAT            = EthType{0x88, 0xA4}
	EthernetPowerlink   = EthType{0x88, 0xAB}
	LLDP                = EthType{0x88, 0xCC}
	SERCOS3             = EthType{0x88, 0xCD}
	HomePlugAVMME       = EthType{0x88, 0xE1}
	MRP                 = EthType{0x88, 0xE3}
	IEEE802_1AE         = EthType{0x88, 0xE5}
	IEEE1588            = EthType{0x88, 0xF7}
	IEEE802_1ag         = EthType{0x89, 0x02}
	FCoE                = EthType{0x89, 0x06}
	FCoEInit            = EthType{0x89, 0x14}
	RoCE                = EthType{0x89, 0x15}
	CTP                 = EthType{0x90, 0x00}
	VeritasLLT          = EthType{0xCA, 0xFE}
)
