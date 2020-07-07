package main

import (
	"fmt"

	"github.com/newtools/zsocket"
	"github.com/newtools/zsocket/nettypes"
)

func main() {
	zs, err := zsocket.NewZSocket(14, zsocket.EnableRX|zsocket.EnableTX, 32768, 128, nettypes.All)
	if err != nil {
		panic(err)
	}
	zs2, err := zsocket.NewZSocket(16, zsocket.EnableRX|zsocket.EnableTX, 32768, 128, nettypes.All)
	if err != nil {
		panic(err)
	}
	go zs.Listen(func(f *nettypes.Frame, frameLen, capturedLen uint16) {
		processFrame(f, capturedLen)
		//fmt.Println(f.String(capturedLen, 0))
		fmt.Println(frameLen, capturedLen)
		_, err := zs2.WriteToBuffer(*f, capturedLen)
		if err != nil {
			panic(err)
		}
		_, err, errs := zs2.FlushFrames()
		if err != nil {
			panic(err)
		}
		if len(errs) > 0 {
			panic(errs)
		}
	})
	zs2.Listen(func(f *nettypes.Frame, frameLen, capturedLen uint16) {
		processFrame(f, capturedLen)
		//fmt.Println(f.String(capturedLen, 0))
		fmt.Println(frameLen, capturedLen)
		_, err := zs.WriteToBuffer(*f, capturedLen)
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
}

func processFrame(f *nettypes.Frame, frameLen uint16) {
	if f.MACEthertype(0) == nettypes.IPv4 {
		ln := frameLen
		mPay, mOff := f.MACPayload(0)
		ln -= mOff
		ip := nettypes.IPv4Packet(mPay)
		if ip.Protocol() == nettypes.TCP {
			iPay, iOff := ip.Payload()
			ln -= iOff
			tcp := nettypes.TCPPacket(iPay)
			tcp.SetChecksum(tcp.CalculateChecksum(ln, ip.SourceIP(), ip.DestinationIP()))
		}
	}
}
