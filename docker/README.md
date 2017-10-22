Docker for RelayNode
=======================
* base on: https://github.com/phusion/baseimage-docker
  * ubuntu 14.04 LTS
* mark sure bitcoind's host & port is current in file `run`
  * `BITCOIND_HOST` is bitcoind's lan/wan ip, do NOT use `127.0.0.1`
  * `BITCOIND_PORT` is default `8333`

**install docker**

```
wget -qO- https://get.docker.com/ | sh
service docker start
service docker status
```

**build image**

```
# supposed Dockerfile path: /root/RelayNode/docker/Dockerfile
cd /root/RelayNode/docker

# before build, please modify `BITCOIND_HOST` in `run`
docker build -t relaynode:0.1 .
```

**start**

```
docker run -it --name relaynode --restart always -d relaynode:0.1
```

**exec docker**

```
docker exec -it relaynode /bin/bash

# eg. watch logs in docker
less /var/log/relaynode.log
```