ZSocket Examples
################

Some examples create complex networking scenarios. A good way to create these is to use docker and network namespaces to create virtual ethernet interfaces
and then use the index of the "outside" interface to open a zsocket (virtual interfaces, in linux, can have a zero-copy socket opened on them just like
a regular interface). For more on how this works checkout [the vethpair creation script](https://github.com/nathanjsweet/zsocket/tree/utils) in this repo.

Print Frame
-----------
This program simply listens to an interface and dumps out what it is receiving in its RX ring (what packets it is receiving).

To set it up simply get the index of the interface you want to listen to using the bash command, `ip link`, and substitute
it in the program. Run the program with `go run 1printframe.go`, and you should see what the interface is receiving.

Simple Bridge
-------------
This program creates a bridge between two interfaces and allows for TCP traffic to pass between them.
