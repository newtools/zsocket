ZSocket
-------
ZSocket is a library that wraps the linux zero-copy socket syscall to create a ring buffer in a memory mapped file.
It also contains some utility functions and types to help with a handful of layer 2, 3, and 4 types.
It is a lot like libcap, except it has easy to understand facilities for writing (injecting packets) to an interface.

ZSocket doesn't contain or wrap any C/C++, and it is lock free and thread safe.

See the examples folder for simple programs that do various things with ZSocket.

Learn how to set up a docker container with a custom veth-pair in the utils folder (useful for setting up
complex virtual networking scenarios)

Play around with FakeInterface to (and its examples folder) to play around with networking protocols.