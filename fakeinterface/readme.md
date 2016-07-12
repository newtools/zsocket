FakeInterface
-------------
FakeInterface is a lib for creating a virtualized interface that you can bridge to real interfaces so that you can play around with networking protocols, and potentially debug issues.
FakeInterface is a work in progress. There are plans to add more types and better logic, but right now the only thing that it contains is an ARP cache, IPv4 support, ICMP ping replies,
and TCP/UDP transfer to open sockets.

See the examples folder for different programs.