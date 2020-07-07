# ZSocket

ZSocket is a library that wraps the linux zero-copy socket syscall to create a ring buffer in a memory mapped file.
It also contains some utility functions and types to help with a handful of layer 2, 3, and 4 types.
It is a lot like libcap, except it has easy to understand facilities for writing (injecting packets) to an interface.

ZSocket doesn't contain or wrap any C/C++, and it is lock free and thread safe.

The following program prints out all know layer types to ZSocket on a given interface:

```go
package main

import (
    "fmt"

    "github.com/newtools/zsocket"
    "github.com/newtools/zsocket/nettypes"
)

func main() {
	// args: interfaceIndex, options, maxFrameSize, and maxTotalFrames

	// inerfaceIndex: the index of the net device you want to open a raw socket to
	// options: RX and TX, or just one or the other?
	// maxFrameSize: must be a power of 2, bigger than zsocket.MinimumFrameSize,
	// 	and smaller than maximum frame size
	// maxTotalFrames: must be at least 16, and be a multiple of 8.
	zs, err := zsocket.NewZSocket(14, zsocket.EnableRX, 2048, 64, nettypes.All)
	// the above will result in a ring buffer of 64 frames at
	// 	(2048 - zsocket.PacketOffset()) *writeable* bytes each
	// 	for a total of 2048*64 bytes of *unswappable* system memory consumed.
	if err != nil {
		panic(err)
	}
	zs.Listen(func(f *nettypes.Frame, frameLen, capturedLen uint16) {
		fmt.Printf(f.String(capturedLen, 0))
	})
}
```

1. See the examples folder for more simple programs that do various things with ZSocket.

2. Learn how to set up a docker container with a custom veth-pair in the utils folder (useful for setting up
complex virtual networking scenarios)

3. Play around with FakeInterface to (and its examples folder) to play around with networking protocols.
