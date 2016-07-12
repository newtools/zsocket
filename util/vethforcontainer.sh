#!/bin/bash
container=$1
ipaddr=$2
vethname=$3
netmask=$4
mtu=$5
# this is a special directory for ip netns, but
# it is actually not the "master" net namespace folder
# each pid can have a network namespace if so desired
# hence the symlinking below
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

localif=veth.${vethname}
tempif=vethc.${vethname}
# create the veth pair
ip link add name $localif type veth peer name $tempif
# set the mtu, turn tso and gso off as they can overflow
# the ring buffer, set to "up"
ip link set $localif mtu $mtu
ethtool -K $localif tso off
ethtool -K $localif gso off
ip link set $localif up

# set the other veth member into the container's network namespace
ip link set $tempif netns $container
# do everything we did to the "sibling" veth pair, but also add
# an ip address and a netmask
ip netns exec $container ethtool -K $tempif tso off
ip netns exec $container ethtool -K $tempif gso off
ip netns exec $container ip link set $tempif up mtu $mtu name $containerif
ip netns exec $container ip addr add $ipaddr dev $containerif
ip netns exec $container ifconfig $containerif netmask $netmask
