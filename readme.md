ZSocket
-------
ZSocket is a library that wraps the linux zero-copy socket syscall to create a ring buffer in a memory mapped file.
It also contains some utility functions and types to help with a handful of layer 2, 3, and 4 types.
It is a lot like libcap, except it has easy to understand facilities for writing (injecting packets) to an interface.

ZSocket doesn't contain or wrap any C/C++, and it is lock free and thread safe.

The following program prints out all know layer types to ZSocket on a given interface:
```go
package main

import (
	"fmt"

	"github.com/nathanjsweet/zsocket"
	"github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
	// args: interface index, options, ring block count, frameOrder, framesInBlock packet types
	// unless you know what you're doing just pay attention to the interface index, whether
	// or not you want the tx ring, rx ring, or both enabled, and what nettype you are listening
	// for.
	zs, err := zsocket.NewZSocket(14, zsocket.ENABLE_RX, 256, zsocket.MAX_ORDER, 4, nettypes.All)
	if err != nil {
		panic(err)
	}
	zs.Listen(func(f *nettypes.Frame, frameLen uint16) {
		fmt.Printf(f.String(frameLen, 0))
	})
}
```

1. See the examples folder for more simple programs that do various things with ZSocket.

2. Learn how to set up a docker container with a custom veth-pair in the utils folder (useful for setting up
complex virtual networking scenarios)

3. Play around with FakeInterface to (and its examples folder) to play around with networking protocols.