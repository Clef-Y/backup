#!/usr/bin/env bash

set -euxo pipefail

IPT="/sbin/iptables"
# the interface which connect to the the internet, 
# it differs if you use wifi or other network device
ITF=enp0s20f0u1c4i2
VITF=vboxnet0
DITF=docker0
LIP="172.20.10.2"    # local IP, check yours IP to modify this

# shortcut of state, we build stateful-firewall
EED="-m state --state ESTABLISHED"
NEW="-m state --state NEW"
NED="-m state --state NEW,ESTABLISHED"
RED="-m state --state RELATED,ESTABLISHED"

# allow dns 
DNS="8.8.8.8
8.8.4.4"

# allow ssh connect to ecs
AWS="54.249.29.30"

# allow openvpn
VPNSERVER="185.159.156.12
185.159.156.11
185.159.157.13
185.159.157.16"

# bogus filter, it shouldn't appear in outside network
# and you can add yours blacklist here
BADIP="0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.20.10.1/24
192.0.2.0/24
192.88.99.0/24
192.88.99.2/32
192.168.0.0/16
192.0.0.0/24
198.18.0.0/15
203.0.113.0/24
224.0.0.0/3
172.104.64.0/19
5.188.0.0/17
23.252.98.104/32
118.244.0.0/16
125.252.0.0/18
46.174.0.0/16
81.17.16.0/20
222.218.0.0/16
203.208.32.0/19
172.217.0.0/16
178.132.0.0/21
74.82.0.0/16
178.73.192.0/18
209.92.0.0/16
173.194.203.109
108.177.98.109
17.143.177.10"

# flush all the old iptables rules 
$IPT -F

# allow local loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT ! -i lo -s 127.0.0.1/8 -j DROP
$IPT -A OUTPUT -o lo -j ACCEPT

# allow ping out, icmp echo-reply and fragment request, drop others to defend ICMP SMURF ATTACKS
$IPT -A INPUT -i $ITF -p icmp --icmp-type 0 -m limit --limit 2/s -d $LIP $RED -j ACCEPT
$IPT -A INPUT -i $ITF -p icmp --icmp-type fragmentation-needed -d $LIP $NEW -j ACCEPT
$IPT -A OUTPUT -o $ITF -p icmp -s $LIP $NED -j ACCEPT 

# Reject bad ip
for ip in $BADIP
    do
        $IPT -A INPUT -i $ITF -s $ip -j DROP
        $IPT -A OUTPUT -o $ITF -d $ip -j DROP
    done

# check tcp syn to defend syn-flood attack
$IPT -A INPUT -i $ITF -p tcp ! --syn $NEW -j DROP

# check tcp fragments which are invalid, then drop them 
$IPT -A INPUT -i $ITF -p tcp -f -j DROP

# DROP ALL INVALID PACKETS
$IPT -A INPUT -i $ITF -m state --state INVALID -j DROP
$IPT -A FORWARD -i $ITF -m state --state INVALID -j DROP
$IPT -A OUTPUT -o $ITF -m state --state INVALID -j DROP

# portscan filter
$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,PSH,URG -j DROP

# string filter and log them
#$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j LOG --log-prefix "bin/sh filterd" --log-level 7
#$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j DROP
#$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j LOG --log-prefix "bin/bash filterd" --log-level 7
#$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j DROP
#$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j LOG --log-prefix "tftp filterd" --log-level 7
#$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j DROP
$IPT -A INPUT -i $ITF -m string --algo bm --string "/dev/null" -j LOG --log-prefix "/dev/null" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "/dev/null" -j DROP

# allow dns
for ip in $DNS
    do
        $IPT -A INPUT -i $ITF -p udp -s $ip --sport 53 -d $LIP $EED -j ACCEPT
        $IPT -A OUTPUT -o $ITF -p udp -s $LIP -d $ip --dport 53 $NED -j ACCEPT
    done

# allow ntp
#$IPT -A INPUT -i $ITF -p udp --sport 123 -d $LIP $EED -j ACCEPT
#$IPT -A OUTPUT -o $ITF -p udp -s $LIP --dport 123 $NED -j ACCEPT

# allow openvpn
for ip in $VPNSERVER
  do
    $IPT -A INPUT -i $ITF -p udp -s $ip --sport 1194 -d $LIP $EED -j ACCEPT
    $IPT -A OUTPUT -o $ITF -p udp -s $LIP -d $ip --dport 1194 $NED -j ACCEPT
  done
$IPT -A INPUT -i tun0 $EED -j ACCEPT
$IPT -A OUTPUT -o tun0 $NED -j ACCEPT

# allow docker
$IPT -A FORWARD -i $DITF $NED -j ACCEPT
$IPT -A FORWARD -o $DITF $EED -j ACCEPT

# allow vitualbox
#$IPT -A INPUT -i $VITF $EED -j ACCEPT
#$IPT -A OUTPUT -o $VITF $NED -j ACCEPT

# if you need open others udp ports, add them above this line

# drop all else udp and log them
$IPT -A INPUT -i $ITF -p udp -j LOG --log-prefix "IPU droped" --log-level 7
$IPT -A INPUT -i $ITF -p udp -j DROP
$IPT -A INPUT -i $ITF -p udp -j LOG --log-prefix "OPU droped" --log-level 7
$IPT -A OUTPUT -o $ITF -p udp -j DROP

# allow ssh
#$IPT -A INPUT -i $ITF -p tcp --dport 20 -d $LIP $NED -j ACCEPT
#$IPT -A OUTPUT -o $ITF -p tcp -s $LIP --sport 20 $EED -j ACCEPT
for ip in $AWS
  do 
    $IPT -A INPUT -i $ITF -p tcp -s $ip --sport 22 -d $LIP $EED -j ACCEPT
    $IPT -A OUTPUT -o $ITF -p tcp -d $ip --dport 22 -s $LIP $NED -j ACCEPT
  done

# allow http and https
$IPT -A INPUT -i $ITF -p tcp -m multiport --sport 80,443 -d $LIP $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p tcp -s $LIP -m multiport --dport 80,443 $NED -j ACCEPT

# if you need open others tcp ports, add these above this line
# drop all else and log them
$IPT -A INPUT -j LOG --log-prefix "IPT_droped" --log-level 7
$IPT -A FORWARD -j LOG --log-prefix "FWD_droped" --log-level 7
$IPT -A OUTPUT -j LOG --log-prefix "OUT_droped" --log-level 7
$IPT -A INPUT -j DROP
$IPT -A FORWARD -j DROP
$IPT -A OUTPUT -j DROP

