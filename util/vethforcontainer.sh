#!/bin/bash
container=$1
ipaddr=$2
mtu=2500
NSDIR=/var/run/netns
containerif=eth1

if [ ! -d $NSDIR ]; then
    mkdir -p $NSDIR
fi

# ensure container is linked in network namespace directory
if [ ! -e $NSDIR/$container ]; then
    # grab container network namespace from docker
    nspid=$(docker inspect -f '{{ .State.Pid }}' $container)

    # set up symlink to container
    rm -f $NSDIR/$container
    ln -s /proc/$nspid/ns/net $NSDIR/$container
fi

localif=veth.${container}
tempif=vethc.${container}
ip link add name $localif type veth peer name $tempif

# add local interface to bridge
ip link set $localif mtu $mtu
ip link set $localif up

ip link set $tempif netns $container
ip netns exec $container ip link set $tempif up mtu $mtu name $containerif
ip netns exec $container ip addr replace $ipaddr dev $containerif
