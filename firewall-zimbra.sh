#!/bin/bash

IPT="/sbin/iptables"
INT="eth0"
INT_ADDR=`ifconfig $WAN | grep -e "inet " | awk {'print $2'}`

function fw_init() {
	echo; echo -e "\033[36m >>> Initilization \e[0m"

	echo 0 > /proc/sys/net/ipv4/ip_forward                        # disable Packet forwarning between interfaces
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts       # ignore ICMP ECHO / and TIMESTAMP requests sent bc
	echo 1 > /proc/sys/net/ipv4/conf/all/log_martians             # log packets with impossible addresses to kernel log
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses # disable logging of bogus responses to broadcast frames
	echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects           # don't send redirects
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route      # don't accept packets with SRR option

	echo " Reset iptables"
	$IPT -F
	$IPT -X
	$IPT -t nat -F
	$IPT -t nat -X
	$IPT -t mangle -F
	$IPT -t mangle -X
	$IPT -t raw -F
	$IPT -t raw -X

	$IPT -A INPUT  -i lo   -j ACCEPT
	$IPT -A OUTPUT -o lo   -j ACCEPT
	echo " Accept localhost"

	$IPT -A OUTPUT -p icmp -j ACCEPT
	$IPT -A INPUT  -p icmp -j ACCEPT
	echo " Accept ICMP"

	$IPT -A INPUT  -p tcp --dport 22 -j ACCEPT
	$IPT -A OUTPUT -p tcp --sport 22 -j ACCEPT
	echo " Accept SSH: 22"
}

function fw_protect() {
	echo; echo -e "\033[36m >>> Protection \e[0m"

	$IPT -A INPUT -p tcp --dport 22 -m recent --rcheck --seconds 60 --hitcount 12 --name SSH -j LOG --log-prefix "SHH "
	$IPT -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 12 --name SSH -j DROP
	$IPT -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH -j ACCEPT
	$IPT -A INPUT  -i $INT -m state --state ESTABLISHED,RELATED -j ACCEPT
	echo " Block brute force attach on SSH"

	$IPT -A INPUT -f -j DROP
	echo " Drop fragment packets"

	$IPT -A OUTPUT -m state --state INVALID -j DROP
	$IPT -A INPUT  -m state --state INVALID -j DROP
	echo " Drop invalid packets"

	echo 1 > /proc/sys/net/ipv4/tcp_syncookies                    
	$IPT -A INPUT -i eth1 -p tcp --syn -m limit --limit 12/second -j ACCEPT 
	echo " Drop SYN flooding"

	$IPT -A INPUT -p tcp -m tcp  --tcp-flags ALL URG,PSH,FIN -j ACCEPT
	echo " Drop xmas-scan packets"

	$IPT -A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 12 -j REJECT
	echo " Limit the number of connections per ip address"

	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter 
	echo " Enable source address validation for spoofing protection"

	$IPT -A INPUT   -p udp --dport 11211 -j DROP
	$IPT -A INPUT   -p tcp --dport 11211 -j DROP
	$IPT -A INPUT   -p udp -s 127.0.0.1 --dport 11211 -j ACCEPT
	$IPT -A INPUT   -p tcp -s 127.0.0.1 --dport 11211 -j ACCEPT
	echo " Block Memcached Exploit"
}

function fw_policy_accept() {
	$IPT -P INPUT   ACCEPT
	$IPT -P OUTPUT  ACCEPT
	$IPT -P FORWARD ACCEPT
}

function fw_policy_drop() {
	$IPT -P INPUT   DROP
	$IPT -P OUTPUT  DROP
	$IPT -P FORWARD DROP
}


function fw_zimbra() {
	echo; echo -e "\033[36m >>> Zimbre rules \e[0m"

	$IPT -A OUTPUT  -p udp --dport 53 -j ACCEPT
	$IPT -A INPUT   -p udp --sport 53 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --dport 53 -j ACCEPT
	$IPT -A INPUT   -p tcp --sport 53 -j ACCEPT
	echo " Accept DNS: 53"

	$IPT -A OUTPUT  -p udp --sport 123 -j ACCEPT
	echo " Accept NTP: 123"

	$IPT -A OUTPUT  -p tcp --dport 137 -j ACCEPT
	$IPT -A INPUT   -p tcp --sport 137 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 137 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 137 -j ACCEPT

	$IPT -A OUTPUT  -p tcp --sport 80 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 80 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 443 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 443 -j ACCEPT
	echo " Accept HTTP/HTTPS: 80,443"

	$IPT -A OUTPUT  -p tcp --sport 389 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 389 -j ACCEPT
	echo " Accept LDAP: 389"

	$IPT -A OUTPUT  -p tcp --sport 143 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 143 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 110 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 110 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --dport 143 -j ACCEPT
	$IPT -A INPUT   -p tcp --sport 143 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --dport 110 -j ACCEPT
	$IPT -A INPUT   -p tcp --sport 110 -j ACCEPT
	echo " Accept POP3/POP3S: 110,995"

	$IPT -A OUTPUT  -p tcp --sport 993 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 993 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 995 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 995 -j ACCEPT
	echo " Accept IMAP/IMAPS: 143,443,993"

	$IPT -A OUTPUT  -p tcp --dport 25 -j ACCEPT
	$IPT -A INPUT   -p tcp --sport 25 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 25 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 25 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 465 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 465 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 587 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 587 -j ACCEPT
	echo " Accept SMTP/SMTPS: 25,465,587"

	$IPT -A OUTPUT  -p tcp --sport 7071 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 7071 -j ACCEPT
	$IPT -A OUTPUT  -p tcp --sport 7073 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 7073 -j ACCEPT
	echo " Accept ZIMBRA ADMIN: 7071"

	$IPT -A OUTPUT  -p tcp --sport 7025 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 7025 -j ACCEPT
	echo " Accept ZIMBRA LMTP: 7025"

	$IPT -A OUTPUT  -p tcp --sport 8443 -j ACCEPT
	$IPT -A INPUT   -p tcp --dport 8443 -j ACCEPT
	echo " Allow ZIMBRA WEB UI: 8443"

	$IPT -N LOG_DROP
	$IPT -A LOG_DROP -j LOG --log-prefix "DROP: "
	$IPT -A LOG_DROP -j DROP
	$IPT -A INPUT    -j LOG_DROP
	$IPT -A OUTPUT   -j LOG_DROP
	echo " Set default policy to DROP"

	echo
	exit 0
}


case "$1" in
	start)
		fw_init
		fw_policy_drop
		fw_protect
		;;

	stop)
		echo "Stopping Firewall..."
		fw_init
		fw_policy_accept
		echo "Firewall Stopped!"
		exit 0
		;;

	restart)
		./firewall.sh stop
		./firewall.sh start
		exit 0
		;;

	status)
		$IPT -S
		exit 0
		;;

	*)
		echo -e "Usage: firewall.sh [status|start|stop|restart]"
		exit 1
		;;
esac

