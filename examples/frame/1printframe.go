package main

import (
	"fmt"

	"github.com/newtools/zsocket"
	"github.com/newtools/zsocket/nettypes"
)

func main() {
	// args: interface index, options, ring block count, frameOrder, framesInBlock packet types
	// unless you know what you're doing just pay attention to the interface index, whether
	// or not you want the tx ring, rx ring, or both enabled, and what nettype you are listening
	// for.
	zs, err := zsocket.NewZSocket(14, zsocket.EnableRX, 2048, 32, nettypes.All)
	if err != nil {
		panic(err)
	}
	zs.Listen(func(f *nettypes.Frame, frameLen, capturedLen uint16) {
		fmt.Printf(f.String(capturedLen, 0))
	})
}
