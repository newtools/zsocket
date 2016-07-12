package fakeinterface

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nathanjsweet/zsocket/inet"
	"github.com/nathanjsweet/zsocket/nettypes"
)

type FakeInterface struct {
	LocalMAC net.HardwareAddr
	LocalIP  *net.IPAddr
	MTU      uint16

	sendListeners []sendListener
	sendLock      *sync.RWMutex
	sockets       map[uint16]FakeIPSocket
	socketKill    map[uint16]bool
	socketLock    *sync.RWMutex

	portsInUse map[uint16]bool
	portLock   *sync.RWMutex

	arpCache     map[string]*arpEntry
	arpCacheLock *sync.RWMutex

	listen uint32

	name string

	rxPackets,
	rxBytes,
	rxErrors,
	rxDropped,
	rxOverruns,
	rxFrame uint64

	txPackets,
	txBytes,
	txErrors,
	txDropped,
	txOverruns,
	txCarrier,
	txCollision uint64
}

type IPPacketOut struct {
	To       *net.IPAddr
	IPPacket nettypes.IPPacket
	Len      uint16
}

type FakeIPSocket interface {
	IPProtocol() nettypes.IPProtocol
	ReceivePacket(*net.IPAddr, nettypes.IPPacket, uint16)
	SendPacketChan() chan *IPPacketOut
}

type sendListener func(*nettypes.Frame, uint16)

type arpEntry struct {
	HardwareAddr net.HardwareAddr
	Time         time.Time
}

func btsEqual(b1, b2 []byte) bool {
	b1l, b2l := len(b1), len(b2)
	if b1l != b2l {
		return false
	}
	for i := 0; i < b1l; i++ {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func copyFx(dst, src []byte, len uint16) {
	copy(dst, src)
}

type byteSize float64

const (
	_           = iota // ignore first value by assigning to blank identifier
	kB byteSize = 1 << (10 * iota)
	mB
	gB
	tB
	pB
	eB
	zB
	yB
)

func (b byteSize) String() string {
	switch {
	case b >= yB:
		return fmt.Sprintf("%.1fYB", b/yB)
	case b >= zB:
		return fmt.Sprintf("%.1fZB", b/zB)
	case b >= eB:
		return fmt.Sprintf("%.1fEB", b/eB)
	case b >= pB:
		return fmt.Sprintf("%.1fPB", b/pB)
	case b >= tB:
		return fmt.Sprintf("%.1fTB", b/tB)
	case b >= gB:
		return fmt.Sprintf("%.1fGB", b/gB)
	case b >= mB:
		return fmt.Sprintf("%.1fMB", b/mB)
	case b >= kB:
		return fmt.Sprintf("%.1fKB", b/kB)
	}
	return fmt.Sprintf("%.1fB", b)
}

func NewFakeInterface(name string, localMAC net.HardwareAddr, localIP *net.IPAddr, mtu uint16) (*FakeInterface, error) {
	if localMAC == nil {
		return nil, fmt.Errorf("must assign a mac address")
	}
	if localIP == nil {
		return nil, fmt.Errorf("must assign an ip address")
	}
	if mtu < 1500 {
		return nil, fmt.Errorf("cannot have an mtu less than 1500")
	}
	fi := new(FakeInterface)
	fi.LocalMAC = localMAC
	fi.LocalIP = localIP
	fi.MTU = mtu

	fi.sendLock = &sync.RWMutex{}
	fi.socketLock = &sync.RWMutex{}

	fi.arpCache = make(map[string]*arpEntry)
	fi.arpCacheLock = &sync.RWMutex{}

	fi.name = name
	return fi, nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) sendEthPayload(to net.HardwareAddr, packet nettypes.EthPacket, length uint16) error {
	l := 14 + length
	atomic.AddUint64(&fi.txPackets, 1)
	atomic.AddUint64(&fi.txBytes, uint64(l))
	if l > fi.MTU {
		atomic.AddUint64(&fi.txOverruns, 1)
		return fmt.Errorf("packet length cannot exceed MTU")
	}
	frame := nettypes.Frame(make([]byte, l))
	copy(frame[14:], packet.Bytes()[:length])
	copy(frame[0:6], to)
	copy(frame[6:12], fi.LocalMAC)
	et := packet.EthType()
	frame[12] = et[0]
	frame[13] = et[1]
	fi.sendLock.RLock()
	defer fi.sendLock.RUnlock()
	wg := sync.WaitGroup{}
	wg.Add(len(fi.sendListeners))
	for _, listener := range fi.sendListeners {
		go func(list sendListener) {
			list(&frame, l)
			wg.Done()
		}(listener)
	}
	wg.Wait()
	return nil
}

func (fi *FakeInterface) sendIPPayload(to *net.IPAddr, packet nettypes.IPPacket, len uint16) error {
	var ha net.HardwareAddr
	var backoffBackoff, backoff uint
	for backoffBackoff, backoff, ha = uint(1), 8, fi.getFromARPCache(to); ha == nil; backoffBackoff, backoff, ha = backoffBackoff<<1, backoff<<backoffBackoff, fi.getFromARPCache(to) {
		if backoff < 30000 {
			targetHA := net.HardwareAddr([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
			broadcast := net.HardwareAddr([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			arp, l := ARPPacket(nettypes.Request, nettypes.IPv4, fi.LocalMAC, fi.LocalIP, targetHA, to)
			fi.sendEthPayload(broadcast, arp, l)
			time.Sleep(time.Millisecond * time.Duration(backoff))
		} else {
			return fmt.Errorf("backoff for ARP request exceeded 30 seconds")
		}
	}
	ipv4, l := IPv4Packet(fi.LocalIP, to, packet.IPProtocol(), packet.Bytes(), len)
	return fi.sendEthPayload(ha, ipv4, l)
}

func (fi *FakeInterface) receiveEthPayload(packet nettypes.Frame, length uint16) error {
	atomic.AddUint64(&fi.rxPackets, 1)
	atomic.AddUint64(&fi.rxBytes, uint64(length))
	macDest := packet.MACDestination()
	pLen := length
	if btsEqual(macDest, fi.LocalMAC) || btsEqual(macDest, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		pType := packet.MACEthertype(0)
		p, mOff := packet.MACPayload(0)
		pLen -= mOff
		switch pType {
		case nettypes.ARP:
			arp := nettypes.ARP_P(p)
			if !fi.processIncomingArpRequest(arp) {
				atomic.AddUint64(&fi.rxDropped, 1)
			}
		case nettypes.IPv4:
			ipv4 := nettypes.IPv4_P(p)
			if ipv4.PacketCorrupt() {
				atomic.AddUint64(&fi.rxDropped, 1)
			}
			ipProto := ipv4.Protocol()
			ipPay, ipOff := ipv4.Payload()
			pLen -= ipOff
			fromIP := net.IPAddr{ipv4.SourceIP(), ""}
			switch ipProto {
			case nettypes.TCP:
				tcp := nettypes.TCP_P(ipPay)
				if tcp.CalculateChecksum(pLen, ipv4.SourceIP(), ipv4.DestinationIP()) != tcp.Checksum() {
					atomic.AddUint64(&fi.rxDropped, 1)
				} else {
					port := tcp.DestinationPort()
					fi.socketLock.RLock()
					if sock, ok := fi.sockets[port]; ok && sock.IPProtocol() == nettypes.TCP {
						sock.ReceivePacket(&fromIP, nettypes.IPPacket(tcp), pLen)
					}
					fi.socketLock.RUnlock()
				}
			case nettypes.UDP:
				udp := nettypes.UDP_P(ipPay)
				csum := udp.Checksum()
				if csum != 0 && csum != udp.CalculateChecksum() {
					atomic.AddUint64(&fi.rxDropped, 1)
				} else {
					port := udp.DestinationPort()
					fi.socketLock.RLock()
					if sock, ok := fi.sockets[port]; ok && sock.IPProtocol() == nettypes.UDP {
						sock.ReceivePacket(&fromIP, nettypes.IPPacket(udp), pLen)
					}
					fi.socketLock.RUnlock()
				}
			case nettypes.ICMP:
				icmp := nettypes.ICMP_P(ipPay)
				if inet.HToNSFS(icmp.CalculateChecksum(pLen)) != icmp.Checksum() {
					atomic.AddUint64(&fi.rxDropped, 1)
				} else {
					typ := icmp.Type()
					if typ == nettypes.EchoRequest {
						icmpP, icmpOff := icmp.Payload()
						pay, l := ICMPRequestReply(nettypes.EchoReply, 0, icmpP, pLen-icmpOff)
						fi.sendIPPayload(&fromIP, pay, l)
					}
				}
			}
		default:
			atomic.AddUint64(&fi.rxErrors, 1)
			return fmt.Errorf("unsupported type %s", pType)
		}
	} else {
		atomic.AddUint64(&fi.rxDropped, 1)
	}
	return nil
}

func (fi *FakeInterface) processIncomingArpRequest(arp nettypes.ARP_P) bool {
	oper := arp.Operation()
	if oper == nettypes.Request {
		if btsEqual(arp.TPA(), fi.LocalIP.IP) {
			ipAddr := net.IPAddr{arp.SPA(), ""}
			hardwareAddr := arp.SHA()
			arp, l := ARPPacket(nettypes.Reply, nettypes.IPv4, fi.LocalMAC, fi.LocalIP, hardwareAddr, &ipAddr)
			fi.sendEthPayload(hardwareAddr, arp, l)
		}
	} else if oper == nettypes.Reply {
		hardwareAddr := arp.SHA()
		ipAddr := net.IPAddr{arp.SPA(), ""}
		fi.addToARPCache(&ipAddr, hardwareAddr)
	} else {
		return false
	}
	return true
}

func (fi *FakeInterface) sendPacketListener(listener sendListener) {
	fi.sendLock.Lock()
	defer fi.sendLock.Unlock()
	fi.sendListeners = append(fi.sendListeners, listener)
}

func (fi *FakeInterface) getFreePort() uint16 {
	fi.portLock.Lock()
	defer fi.portLock.Unlock()
	p := uint16(6000)
	for {
		if _, ok := fi.portsInUse[p]; ok {
			p++
		} else {
			fi.portsInUse[p] = true
			return p
		}
	}
}

func (fi *FakeInterface) returnPort(p uint16) {
	fi.portLock.Lock()
	defer fi.portLock.Unlock()
	delete(fi.portsInUse, p)
}

func (fi *FakeInterface) socketLoop(socket FakeIPSocket, port uint16) {
	ch := socket.SendPacketChan()
	for {
		fi.socketLock.RLock()
		if kill, ok := fi.socketKill[port]; !ok || kill {
			fi.socketLock.RUnlock()
			break
		}
		fi.socketLock.RUnlock()
		select {
		case ipOut := <-ch:
			fi.sendIPPayload(ipOut.To, ipOut.IPPacket, ipOut.Len)
		case <-time.After(time.Millisecond):
			runtime.Gosched()
		}
	}
}

func (fi *FakeInterface) addToARPCache(ipAddr *net.IPAddr, hardwareAddr net.HardwareAddr) {
	arpEntry := new(arpEntry)
	arpEntry.HardwareAddr = hardwareAddr
	fi.arpCacheLock.Lock()
	defer fi.arpCacheLock.Unlock()
	arpEntry.Time = time.Now().Add(time.Second * 30)
	fi.arpCache[ipAddr.String()] = arpEntry

}

func (fi *FakeInterface) getFromARPCache(ipAddr *net.IPAddr) net.HardwareAddr {
	fi.arpCacheLock.RLock()
	defer fi.arpCacheLock.RUnlock()
	ha, ok := fi.arpCache[ipAddr.String()]
	if !ok || time.Now().After(ha.Time) {
		return nil
	}
	return ha.HardwareAddr
}

func (fi *FakeInterface) OpenSocket(socket FakeIPSocket, assignPort bool, port uint16) (uint16, error) {
	fi.socketLock.Lock()
	defer fi.socketLock.Unlock()
	if assignPort {
		port = fi.getFreePort()
	} else {
		fi.portLock.Lock()
		defer fi.portLock.Unlock()
		if _, ok := fi.portsInUse[port]; ok {
			return 0, fmt.Errorf("port %v is already in use", port)
		}
	}
	fi.portsInUse[port] = true
	fi.socketKill[port] = false
	fi.sockets[port] = socket
	go fi.socketLoop(socket, port)
	return port, nil
}

func (fi *FakeInterface) CloseSocket(port uint16) error {
	fi.socketLock.Lock()
	defer fi.socketLock.Unlock()
	fi.returnPort(port)
	delete(fi.socketKill, port)
	if _, ok := fi.sockets[port]; !ok {
		return fmt.Errorf("socket is not open")
	}
	delete(fi.sockets, port)
	return nil
}

func (fi *FakeInterface) MaxPackets() uint32 {
	return 1000
}

func (fi *FakeInterface) MaxPacketSize() uint16 {
	return uint16(fi.MTU)
}

func (fi *FakeInterface) WrittenPackets() uint32 {
	return 0
}

func (fi *FakeInterface) Listen(fx func(*nettypes.Frame, uint16)) error {
	atomic.SwapUint32(&fi.listen, 1)
	fi.sendPacketListener(fx)
	for {
		if atomic.LoadUint32(&fi.listen) == 0 {
			return fmt.Errorf("interface socket closed")
		}
		time.Sleep(time.Second)
	}
}

func (fi *FakeInterface) WriteToBuffer(buf []byte, l uint16) (int32, error) {
	return fi.CopyToBuffer(buf, l, copyFx)
}

func (fi *FakeInterface) CopyToBuffer(buf []byte, l uint16, copyFx func(dst, src []byte, l uint16)) (int32, error) {
	err := fi.receiveEthPayload(nettypes.Frame(buf[:l]), uint16(l))
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (fi *FakeInterface) FlushFrames() (uint, error, []error) {
	return 0, nil, nil
}

func (fi *FakeInterface) Close() error {
	atomic.SwapUint32(&fi.listen, 0)
	return nil
}

func (fi *FakeInterface) String() string {
	var status string
	if atomic.LoadUint32(&fi.listen) == 1 {
		status = "UP,RUNNING"
	} else {
		status = "DOWN"
	}
	rxBytes := atomic.LoadUint64(&fi.rxBytes)
	rxBytesF := byteSize(float64(rxBytes))
	txBytes := atomic.LoadUint64(&fi.txBytes)
	txBytesF := byteSize(float64(txBytes))
	return fmt.Sprintf("%s: ", fi.name) + fmt.Sprintf("flags=4163<%s> mtu %v\n", status, fi.MTU) +
		fmt.Sprintf("\tinet %s prefixlen 64 scopeid 0x20<link>\n", fi.LocalIP) +
		fmt.Sprintf("\tether %s txqueuelen 1000 (Ethernet)\n", fi.LocalMAC) +
		fmt.Sprintf("\tRX packets %d bytes %d (%s)\n", atomic.LoadUint64(&fi.rxPackets), rxBytes, rxBytesF) +
		fmt.Sprintf("\tRX errors %d dropped %d overruns %d frame %d\n", atomic.LoadUint64(&fi.rxErrors),
			atomic.LoadUint64(&fi.rxDropped), atomic.LoadUint64(&fi.rxOverruns), atomic.LoadUint64(&fi.rxFrame)) +
		fmt.Sprintf("\tTX packets %d bytes %d (%s)\n", atomic.LoadUint64(&fi.txPackets), txBytes, txBytesF) +
		fmt.Sprintf("\tTX errors %d dropped %d overruns %d carrier %d collision %d\n", atomic.LoadUint64(&fi.txErrors),
			atomic.LoadUint64(&fi.txDropped), atomic.LoadUint64(&fi.txOverruns), atomic.LoadUint64(&fi.txCarrier), atomic.LoadUint64(&fi.txCollision))
}
