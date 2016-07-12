FakeInterface
-------------
FakeInterface is a lib for creating a virtualized interface that you can bridge to real interfaces so that you can play around with networking protocols, and potentially debug issues.
FakeInterface is a work in progress. There are plans to add more types and better logic, but right now the only thing that it contains is an ARP cache, IPv4 support, ICMP ping replies,
and TCP/UDP transfer to open sockets. 
package main

import (
	"fmt"
	"net"
	"time"

	"github.com/nathanjsweet/zsocket"
	fi "github.com/nathanjsweet/zsocket/fakeinterface"
	"github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
	zs, err := zsocket.NewZSocket(18, zsocket.ENABLE_RX|zsocket.ENABLE_TX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	fip := net.IPAddr{net.IP([]byte{192, 0, 0, 3}), ""}
	fak, err := fi.NewFakeInterface("fake1", net.HardwareAddr([]byte{0x1e, 0x44, 0x70, 0x3c, 0x66, 0xe3}), &fip, 30000)
	go func() {
		for {
			fmt.Printf("%s\n", fak)
			time.Sleep(time.Second * time.Duration(10))
		}
	}()
	if err != nil {
		panic(err)
	}
	go func() {
		panic(zs.Listen(func(f *nettypes.Frame, frameLen uint16) {
			fmt.Println("20:")
			fmt.Println(f.String(frameLen, 0))
			processFrame(f, frameLen)
			_, err := fak.WriteToBuffer(*f, frameLen)
			if err != nil {
				panic(err)
			}
			_, err, errs := fak.FlushFrames()
			if err != nil {
				panic(err)
			}
			if len(errs) > 0 {
				panic(errs)
			}
		}))
	}()
	err = fak.Listen(func(f *nettypes.Frame, frameLen uint16) {
		fmt.Println("fake:")
		fmt.Println(f.String(frameLen, 0))
		processFrame(f, frameLen)
		_, err := zs.WriteToBuffer(*f, frameLen)
		if err != nil {
			panic(err)
		}
		_, err, errs := zs.FlushFrames()
		if err != nil {
			panic(err)
		}
		if len(errs) > 0 {
			panic(errs)
		}
	})
	if err != nil {
		panic(err)
	}
}

func processFrame(f *nettypes.Frame, frameLen uint16) {
	if f.MACEthertype(nettypes.NotTagged) == nettypes.IPv4 {
		ln := frameLen
		mPay, mOff := f.MACPayload(nettypes.NotTagged)
		ln -= mOff
		ip := nettypes.IPv4_P(mPay)
		iPay, iOff := ip.Payload()
		ln -= iOff
		switch ip.Protocol() {
		case nettypes.TCP:
			tcp := nettypes.TCP_P(iPay)
			tcp.SetChecksum(tcp.CalculateChecksum(ln, ip.SourceIP(), ip.DestinationIP()))
		case nettypes.UDP:
			udp := nettypes.UDP_P(iPay)
			udp.SetChecksum(udp.CalculateChecksum())
		}
	}
}

```