package main

import (
	"fmt"

	"github.com/nathanjsweet/zsocket"
	"github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
	zs, err := zsocket.NewZSocket(18, zsocket.ENABLE_RX|zsocket.ENABLE_TX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	zs2, err := zsocket.NewZSocket(22, zsocket.ENABLE_RX|zsocket.ENABLE_TX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	go zs.Listen(func(f *nettypes.Frame, frameLen uint16) {
		processFrame(f, frameLen)
		fmt.Println("18:")
		fmt.Println(f.String(frameLen, 0))
		_, err := zs2.WriteToBuffer(*f, frameLen)
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
	zs2.Listen(func(f *nettypes.Frame, frameLen uint16) {
		processFrame(f, frameLen)
		fmt.Println("22:")
		fmt.Println(f.String(frameLen, 0))
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
}

func processFrame(f *nettypes.Frame, frameLen uint16) {
	if f.MACEthertype(0) == nettypes.IPv4 {
		ln := frameLen
		mPay, mOff := f.MACPayload(0)
		ln -= mOff
		ip := nettypes.IPv4_P(mPay)
		if ip.Protocol() == nettypes.TCP {
			iPay, iOff := ip.Payload()
			ln -= iOff
			tcp := nettypes.TCP_P(iPay)
			tcp.SetChecksum(tcp.CalculateChecksum(ln, ip.SourceIP(), ip.DestinationIP()))
		}
	}
}
