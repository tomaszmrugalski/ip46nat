#!/bin/sh
# This is an example script for ip46nat. It assumes the following network:
#
# IPv4 network
#                      br-lan     eth0.1
#  v4 Host ---------------- ip46nat ---------------- v6 Host
# 192.168.1.5    192.168.1.1    2000::1/64    2000::a00:2/64
#
# v4 host has to have default gateway set to 192.168.1.1
# v6 host has to have 3000::/64 prefix routed to 2000::1
#
# v4 host connects to 10.0.0.2. The outgoing packet is 192.168.1.5 -> 10.0.0.2
# It is translated to 3000::c0a8:105 -> 2000::a00:2. v6 host receives packets
# and responds with 2000::a00:2 -> 3000::c0a8:105. This gets translated back to
# 10.0.0.2 -> 192.168.1.5.
#
# Note that you cannot use ping as ICMP for v4 and for v6 are different protocols.
# You can use most TCP (e.g. http or windows printing) and most UDP protocols.

ip a a 2000::1/64 dev eth0.1
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding

iptables -I OUTPUT -d 192.168.1.0/24 -p ICMP --icmp-type network-unreachable -j DROP
ip6tables -I OUTPUT -s 2000::1 -p icmpv6 --icmpv6-type destination-unreachable -j DROP
insmod /root/mod/ip46nat.ko prefixlan=3000:: prefixwan=2000:: v4addr=192.168.1.0 debug=0
