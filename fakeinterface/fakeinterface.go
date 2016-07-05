package fakeinterface

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nathanjsweet/zsocket/nettypes"
)

type SendReceiveListener func(nettypes.Frame, uint16)

type FakeInterface struct {
	LocalMAC net.HardwareAddr
	LocalIP  *net.IPAddr
	MTU      uint16

	sendListeners    []SendReceiveListener
	sendLock         *sync.RWMutex
	receiveListeners []SendReceiveListener
	receiveLock      *sync.RWMutex

	arpCache     map[string]*ARPEntry
	arpCacheLock *sync.RWMutex
}

type ARPEntry struct {
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
	fi.receiveLock = &sync.RWMutex{}

	fi.arpCache = make(map[string]*ARPEntry)
	fi.arpCacheLock = &sync.RWMutex{}
	return fi, nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) SendEthPayload(to net.HardwareAddr, packet nettypes.EthPacket, length uint16) error {
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
		go func(list SendReceiveListener) {
			list(frame, l)
			wg.Done()
		}(listener)
	}
	wg.Wait()
	return nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) SendIPPayload(to *net.IPAddr, packet nettypes.IPPacket, len uint16) error {
	var ha net.HardwareAddr
	var backoffBackoff, backoff uint
	for backoffBackoff, backoff, ha = uint(1), 1, fi.GetFromARPCache(to); ha == nil; backoffBackoff, backoff, ha = backoffBackoff<<1, backoff<<backoffBackoff, fi.GetFromARPCache(to) {
		if backoff < 30000 {
			//send packet
			time.Sleep(time.Millisecond * time.Duration(backoff))
		} else {
			return fmt.Errorf("backoff for ARP request exceeded 30 seconds")
		}
	}
	ipv4, l := IPv4Packet(fi.LocalIP, to, packet.IPProtocol(), packet.Bytes(), len)
	return fi.SendEthPayload(ha, ipv4, l)
}

// This  function will Receive a packet to the interface
func (fi *FakeInterface) ReceiveEthPayload(from net.HardwareAddr, packet nettypes.EthPacket, len uint32) error {

	return nil
}

func (fi *FakeInterface) SendPacketListener(listener SendReceiveListener) {
	fi.sendLock.Lock()
	defer fi.sendLock.Unlock()
	fi.sendListeners = append(fi.sendListeners, listener)
}

func (fi *FakeInterface) ReceivePacketListener(listener SendReceiveListener) {
	fi.receiveLock.Lock()
	defer fi.receiveLock.Unlock()
	fi.receiveListeners = append(fi.receiveListeners, listener)
}

func (fi *FakeInterface) AddToARPCache(ipAddr *net.IPAddr, hardwareAddr net.HardwareAddr) {
	arpEntry := new(ARPEntry)
	arpEntry.HardwareAddr = hardwareAddr
	fi.arpCacheLock.Lock()
	defer fi.arpCacheLock.Unlock()
	arpEntry.Time = time.Now().Add(time.Second * 30)
	fi.arpCache[ipAddr.String()] = arpEntry

}

func (fi *FakeInterface) GetFromARPCache(ipAddr *net.IPAddr) net.HardwareAddr {
	fi.arpCacheLock.RLock()
	defer fi.arpCacheLock.RUnlock()
	ha, ok := fi.arpCache[ipAddr.String()]
	if !ok || time.Now().After(ha.Time) {
		return nil
	}
	return ha.HardwareAddr
}
