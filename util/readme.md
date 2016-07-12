Creating A Docker Container With A Custom Interface
---------------------------------------------------
Create a docker container with ubuntu:14.04 (or your favorite linux flavor).
The `/sbin/init` command runs systemd and persistes a container without a "master"
process, per usual (actually init is a user space process, and is pid-1 in linux).
```sh
docker run -d --name container1 ubuntu:14.04 /sbin/init
```

Create a virtual ethernet pair (learn about veth pairs to understand what they do),
and "throw" one member of the pair into your container's network namespace (read
the script to understand what it's doing).
```sh
./vethforcontainer.sh container1 192.0.0.1 c01 255.255.255.0 30000
```

Check out the new ethernet interface we just placed into the container:
```sh
docker exec -it container1 ifconfig
```
