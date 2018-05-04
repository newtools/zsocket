FakeInterface Examples
----------------------
Some examples create complex networking scenarios. A good way to create these is to use docker and network namespaces to create virtual ethernet interfaces
and then use the index of the "outside" interface to open a zsocket (virtual interfaces, in linux, can have a zero-copy socket opened on them just like
a regular interface). For more on how this works checkout [the vethpair creation script](https://github.com/newtools/zsocket/tree/master/util) in this repo.

Simple Bridge
-------------
Creates a virtual bridge between to interfaces. If you ping with the non-virtual interface you will get a response.

