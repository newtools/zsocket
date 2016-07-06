package fakeinterface

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nathanjsweet/zsocket/nettypes"
)

type FakeInterface struct {
	LocalMAC net.HardwareAddr
	LocalIP  *net.IPAddr
	MTU      uint16
	Dropped  uint64

	sendListeners []sendListener
	sendLock      *sync.RWMutex
	sockets       map[uint16]FakeSocket
	socketKill    map[uint16]bool
	socketLock    *sync.RWMutex

	portsInUse map[uint16]bool
	portLock   *sync.RWMutex

	arpCache     map[string]*arpEntry
	arpCacheLock *sync.RWMutex
}

type IPPacketOut struct {
	To       *net.IPAddr
	IPPacket nettypes.IPPacket
	Len      uint16
}

type FakeSocket interface {
	IPProtocol() nettypes.IPProtocol
	ReceivePacket(nettypes.IPPacket)
	SendPacketChan() chan *IPPacketOut
}

type sendListener func(*nettypes.Frame, uint16)

type arpEntry struct {
	HardwareAddr net.HardwareAddr
	Time         time.Time
}

func NewFakeInterface(localMAC net.HardwareAddr, localIP *net.IPAddr, mtu uint16) (*FakeInterface, error) {
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
	return fi, nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) sendEthPayload(to net.HardwareAddr, packet nettypes.EthPacket, length uint16) error {
	if length > fi.MTU {
		return fmt.Errorf("packet length cannot exceed MTU")
	}
	l := 14 + length
	frame := nettypes.Frame(make([]byte, l))
	copy(frame[0:6], to)
	copy(frame[6:12], fi.LocalMAC)
	et := packet.EthType()
	frame[12] = et[0]
	frame[13] = et[1]
	copy(frame[14:], packet.Bytes()[:length])
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

// This function will Send a packet from the interface
func (fi *FakeInterface) sendIPPayload(to *net.IPAddr, packet nettypes.IPPacket, len uint16) error {
	var ha net.HardwareAddr
	var backoffBackoff, backoff uint
	for backoffBackoff, backoff, ha = uint(1), 1, fi.getFromARPCache(to); ha == nil; backoffBackoff, backoff, ha = backoffBackoff<<1, backoff<<backoffBackoff, fi.getFromARPCache(to) {
		if backoff < 30000 {
			targetHA := net.HardwareAddr([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			arp, l := ARPPacket(nettypes.Request, nettypes.IPv4, fi.LocalMAC, fi.LocalIP, targetHA, to)
			fi.sendEthPayload(targetHA, arp, l)
			time.Sleep(time.Millisecond * time.Duration(backoff))
		} else {
			return fmt.Errorf("backoff for ARP request exceeded 30 seconds")
		}
	}
	ipv4, l := IPv4Packet(fi.LocalIP, to, packet.IPProtocol(), packet.Bytes(), len)
	return fi.sendEthPayload(ha, ipv4, l)
}

// This  function will Receive a packet to the interface
func (fi *FakeInterface) receiveEthPayload(packet nettypes.Frame, length uint16) error {
	macDest := packet.MACDestination()
	if btsEqual(macDest, fi.LocalMAC) || btsEqual(macDest, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		pType := packet.MACEthertype(0)
		p, l := packet.MACPayload(0)
		switch pType {
		case nettypes.ARP:
			arp := nettypes.ARP_P(p)
			if !fi.processIncomingArpRequest(arp) {
				atomic.AddUint64(&fi.Dropped, 1)
			}
		case nettypes.IPv4:
			ipv4 := nettypes.IPv4_P(p)
			if ipv4.PacketCorrupt() {
				atomic.AddUint64(&fi.Dropped, 1)
			}
			ipProto := ipv4.Protocol()
			ipPay, ipL := ipv4.Payload()
			switch ipProto {
			case nettypes.TCP:
				tcp := nettypes.TCP_P(ipPay)
				if tcp.CalculateChecksum(ipL, ipv4.SourceIP(), ipv4.DestinationIP()) != tcp.Checksum() {
					atomic.AddUint64(&fi.Dropped, 1)
				} else {
					port := tcp.DestinationPort()
					fi.socketLock.RLock()
					if sock, ok := fi.sockets[port]; ok && sock.IPProtocol() == nettypes.TCP {
						sock.ReceivePacket(nettypes.IPPacket(tcp))
					}
					fi.socketLock.RUnlock()
				}
			case nettypes.UDP:
				udp := nettypes.UDP_P(ipPay)
				csum := udp.Checksum()
				if csum != 0 && csum != udp.CalculateChecksum() {
					atomic.AddUint64(&fi.Dropped, 1)
				} else {
					port := udp.DestinationPort()
					fi.socketLock.RLock()
					if sock, ok := fi.sockets[port]; ok && sock.IPProtocol() == nettypes.UDP {
						sock.ReceivePacket(nettypes.IPPacket(udp))
					}
					fi.socketLock.RUnlock()
				}
			case nettypes.ICMP:
				icmp := nettypes.ICMP_P(ipPay)
				if icmp.CalculateChecksum(ipL) != icmp.Checksum() {
					atomic.AddUint64(&fi.Dropped, 1)
				}
			}
		default:
			return fmt.Errorf("unsupported type %s", pType)
		}
	} else {
		atomic.AddUint64(&fi.Dropped, 1)
		drop = true
	}
	return nil
}

func (fi *FakeInterface) processIncomingArpRequest(arp nettypes.ARP_P) bool {
	oper := arp.Operation()
	if oper == nettypes.Request {
		if btsEqual(arp.TPA(), fi.LocalIP.IP) {
			ipAddr := net.IPAddr{arp.SPA(), ""}
			hardwareAddr := arp.SHA()
			arp, l := ARPPacket(nettypes.Reply, nettypes.IPv4, hardwareAddr, &ipAddr, fi.LocalMAC, fi.LocalIP)
			fi.sendEthPayload(hardwareAddr, arp, l)
		}
	} else if oper == nettypes.Reply {
		hardwareAddr := arp.THA()
		ipAddr := net.IPAddr{arp.TPA(), ""}
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

func (fi *FakeInterface) OpenSocket(socket FakeSocket, assignPort bool, port uint16) (uint16, error) {
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

func (fi *FakeInterface) socketLoop(socket FakeSocket, port uint16) {
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

func (fi *FakeInterface) MaxPackets() uint32 {
	return 1000
}

func (fi *FakeInterface) MaxPacketSize() uint32 {
	return uint32(fi.MTU)
}

func (fi *FakeInterface) WrittenPackets() uint32 {
	return 0
}

func (fi *FakeInterface) Listen(fx func(*nettypes.Frame, uint16)) {
	fi.sendPacketListener(fx)
}

func copyFx(dst, src []byte, len uint32) {
	copy(dst, src)
}

func (fi *FakeInterface) WriteToBuffer(buf []byte, l uint32) (int32, error) {
	fi.CopyToBuffer(buf, l, copyFx)
}

func (fi *FakeInterface) CopyToBuffer(buf []byte, l uint32, copyFx func(dst, src []byte, l uint32)) (int32, error) {
	bts := make([]byte, l)
	copyFx(bts, buf, l)
	err := fi.ReceiveEthPayload(nettypes.Frame(bts), uint16(l))
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (fi *FakeInterface) FlushFrames() (uint, error, []error) {
	return 0, nil, nil
}

func (fi *FakeInterface) Close() error {
	return nil
}
