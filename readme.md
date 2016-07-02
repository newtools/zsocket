ZSocket
-------
ZSocket is a library that wraps the linux zero-copy socket syscall to create a ring buffer in a memory mapped file.
It also contains some utility functions and types to help with a handful of layer 2, 3, and 4 types.
It is a lot like libcap, except it has easy to understand facilities for writing (injecting packets) to an interface.

ZSocket doesn't contain or wrap any C/C++, and it is lock free and thread safe.

Example
-------
The following program will print out any recognized nettypes, going down to layer 4.
You can find your interface index number by running `ip link`.
```go
package  main
import (
       "github.com/nathanjsweet/zsocket"
       "github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
     // args: interface index, options, ring block count, frameOrder, framesInBlock packet types
     // unless you know what you're doing just pay attention to the interface index, whether
     // or not you want the tx ring, rx ring, or both enabled, and what nettype you are listening
     // for.
     zs, err := zsocket.NewZSocket(15, zsocket.ENABLE_RX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
     if err != nil {
        panic(err)
     }
     zs.Listen(func(f *nettypes.Frame, frameLen uint32) {
        fmt.Printf(f.String(frameLen, 0))
     })
}
```

The following code will create a simple bridge between two interfaces, while printing their frames, that will allow tcp  through (no other checksum dependent layer 4 types though):
```go
package main

import (
	"fmt"

	"github.com/nathanjsweet/zsocket"
	"github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
	zs, err := zsocket.NewZSocket(25, zsocket.ENABLE_RX|zsocket.ENABLE_TX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	zs2, err := zsocket.NewZSocket(27, zsocket.ENABLE_RX|zsocket.ENABLE_TX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	go zs.Listen(func(f *nettypes.Frame, frameLen uint32) {
		processFrame(f, frameLen)
		fmt.Println("25:")
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
	zs2.Listen(func(f *nettypes.Frame, frameLen uint32) {
		processFrame(f, frameLen)
		fmt.Println("27:")
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

func processFrame(f *nettypes.Frame, frameLen uint32) {
	if f.MACEthertype() == nettypes.IPv4 {
		ln := frameLen
		mPay, mOff := f.MACPayload()
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
```