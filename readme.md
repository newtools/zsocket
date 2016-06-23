ZSocket
-------
ZSocket is a library that wraps the linux zero-copy socket syscall to create a ring buffer in a memory mapped file.
It also contains some utility functions and types to help with a handful of layer 2 and layer 3 types.
It is a lot like libcap, except it has easy to understand facilities for Writing to and interface.
Example
-------
The following program will print out any recognized nettypes, going down to layer 3.
You can find your interface index number by running `ip link`.
```go
package  main
import (
       "github.com/nathanjsweet/zsocket"
       "github.com/nathanjsweet/zsocket/nettypes"
)

func main() {
     // args: interface index, options, ring block numbers, packet types
     zs, err := zsocket.NewZSocket(15, zsocket.ENABLE_RX, 256, nettypes.All)
     if err != nil {
        panic(err)
     }
     zs.Listen(func(f *nettypes.Frame, frameLen uint32) {
        fmt.Printf(f.String(frameLen, 0))
     })
}
``` 

