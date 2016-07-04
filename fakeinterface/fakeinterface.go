package fakeinterface

import (
	"fmt"
	"net"
	"sync"

	"github.com/nathanjsweet/zsocket/nettypes"
)

type SendReceiveListener func(nettypes.Frame, uint32)

type FakeInterface struct {
	LocalMAC net.HardwareAddr
	LocalIP  *net.IPAddr
	MTU      uint32

	sendListeners    []SendReceiveListener
	receiveListeners []SendReceiveListener

	arpCache      map[string]net.HardwareAddr
	arpCacheLock  *sync.RWMutex
	arpSignal     map[string]*sync.Cond
	arpSignalLock *sync.RWMutex
}

type fakeLock struct{}

func (fl *fakeLock) Lock()   {}
func (fl *fakeLock) Unlock() {}

func NewFakeInterface(localMAC net.HardwareAddr, localIP *net.IPAddr, mtu uint32) (*FakeInterface, error) {
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

	fi.arpCache = make(map[string]net.HardwareAddr)
	fi.arpCacheLock = &sync.RWMutex{}
	fi.arpSignal = make(map[string]*sync.Cond)
	fi.arpSignalLock = &sync.RWMutex{}
	return fi, nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) SendEthPacket(to net.HardwareAddr, packet nettypes.EthPacket, len uint32) error {
	if len > fi.MTU {
		return fmt.Errorf("packet length cannot exceed MTU")
	}
	return nil
}

// This function will Send a packet from the interface
func (fi *FakeInterface) SendIPPacket(to *net.IPAddr, packet nettypes.IPPacket, len uint32) error {
	if ha := fi.GetFromARPCache(to); ha == nil {
		var c *sync.Cond
		var ok bool
		fi.arpSignalLock.Lock()
		if c, ok = fi.arpSignal[to.String()]; !ok {
			c = sync.NewCond(&fakeLock{})
			fi.arpSignal[to.String()] = c
		}
		fi.arpSignalLock.Unlock()

		c.Wait()
	}
	return nil
}

// This  function will Receive a packet to the interface
func (fi *FakeInterface) ReceiveEthPacket(from net.HardwareAddr, packet nettypes.EthPacket, len uint32) error {

	return nil
}

func (fi *FakeInterface) SendPacketListener(listener SendReceiveListener) {

}

func (fi *FakeInterface) ReceivePacketListener(listener SendReceiveListener) {

}

func (fi *FakeInterface) AddToARPCache(ipAddr *net.IPAddr, hardwareAddr net.HardwareAddr) {
	fi.arpCacheLock.Lock()
	defer fi.arpCacheLock.Unlock()
	fi.arpCache[ipAddr.String()] = hardwareAddr
	fi.arpSignalLock.RLock()
	defer fi.arpSignalLock.RUnlock()
	if haSig, ok := fi.arpSignal[ipAddr.String()]; ok {
		haSig.Broadcast()
	}
}

func (fi *FakeInterface) GetFromARPCache(ipAddr *net.IPAddr) net.HardwareAddr {
	fi.arpCacheLock.RLock()
	defer fi.arpCacheLock.RUnlock()
	ha, ok := fi.arpCache[ipAddr.String()]
	if !ok {
		return nil
	}
	return ha
}
