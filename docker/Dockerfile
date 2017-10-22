#
# Dockerfile
#
# @author zhibiao.pan@bitmain.com
# @since 2016-01
#
#
FROM phusion/baseimage:0.9.16
MAINTAINER PanZhibiao <zhibiao.pan@bitmain.com>

ENV HOME /root
ENV TERM xterm
CMD ["/sbin/my_init"]

# install packages
RUN apt-get update
RUN apt-get install -y git build-essential yasm

# build
RUN cd /root \
  && git clone https://github.com/TheBlueMatt/RelayNode.git \
  && cd RelayNode/c++ \
  && make

# daemons
RUN mkdir /etc/service/relaynode
ADD run /etc/service/relaynode/run
RUN chmod +x /etc/service/relaynode/run
