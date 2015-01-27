#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import re
import time
import sys
import argparse
from subprocess import Popen, PIPE, check_output
import logging

# Basic configuration
DN = open(os.devnull, 'w')

# Console colors
W = '\033[0m'    # white (normal)
R = '\033[31m'   # red
G = '\033[32m'   # green
O = '\033[33m'   # orange
B = '\033[34m'   # blue
P = '\033[35m'   # purple
C = '\033[36m'   # cyan
GR = '\033[37m'  # gray
T = '\033[93m'   # tan

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser(description='Create an access point to share internet connexion.')
    parser.add_argument('inet_iface', help='Choose an interface connected to internet.')
    parser.add_argument('ap_iface', help='Choose an interface to be used as access point.')
    parser.add_argument('essid', help='Specifie a ESSID for your access point')
    parser.add_argument('-c', '--channel', help='Choose the channel. Default value is 1', default='1')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')

    return parser.parse_args()

def shutdown(interfaces):
    """
    Shutdowns program.
    """
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dnsmasq')
    os.system('pkill hostapd')
    if os.path.isfile('/tmp/hostapd.conf'):
        os.remove('/tmp/hostapd.conf')
    if os.path.isfile('/tmp/dhcpd.conf'):
        os.remove('/tmp/dhcpd.conf')
    reset_interfaces(interfaces)
    print '\n[' + R + '!' + W + '] Closing'
    sys.exit(0)

def reset_interfaces(interfaces):
    for iface in interfaces:
        if 'mon' in iface:
            Popen(['airmon-ng', 'stop', iface], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
            Popen(['iwconfig', iface, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)

def start_ap(ap_iface, channel, essid, args):
    print '['+T+'*'+W+'] Starting the access point...'
    config = ('interface=%s\n'
              #'driver=nl80211\n'
              'ssid=%s\n'
              'hw_mode=g\n'
              'channel=%s\n'
              'macaddr_acl=0\n'
              'ignore_broadcast_ssid=0\n'
             )
    with open('/tmp/hostapd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (ap_iface, essid, channel))

    Popen(['hostapd', '/tmp/hostapd.conf'], stdout=DN, stderr=DN)
    try:
        time.sleep(6) # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        shutdown([])

def dhcp_conf(interface):
    
    config = (# disables dnsmasq reading any other files like /etc/resolv.conf for nameservers
              'no-resolv\n'
              # Interface to bind to
              'interface=%s\n'
              # Specify starting_range,end_range,lease_time
              'dhcp-range=%s\n'
              'address=/#/192.168.100.1'
              )
    with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
         # subnet, range, router, dns
         dhcpconf.write(config % (interface, '192.168.100.2,192.168.100.254,12h'))
    return '/tmp/dhcpd.conf'

def dhcp(dhcpconf, ap_iface):
    os.system('echo > /var/lib/misc/dnsmasq.leases')
    dhcp = Popen(['dnsmasq', '-C', dhcpconf], stdout=PIPE, stderr=DN)
    Popen(['ifconfig', str(ap_iface), 'up', '192.168.100.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)

def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input('['+T+'*'+W+'] isc-dhcp-server not found in /usr/sbin/hostapd, install now? [y/n] ')
        if install == 'y':
            os.system('apt-get -y install hostapd')
        else:
            sys.exit('['+R+'-'+W+'] hostapd not found in /usr/sbin/hostapd')

def get_dnsmasq():
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        install = raw_input('['+T+'*'+W+'] dnsmasq not found in /usr/sbin/dnsmasq, install now? [y/n] ')
        if install == 'y':
            os.system('apt-get -y install dnsmasq')
        else:
            sys.exit('['+R+'-'+W+'] dnsmasq not found in /usr/sbin/dnsmasq')

if __name__ == "__main__":

    # Parse args
    args = parse_args()
    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')
    # Get hostapd if needed
    get_hostapd()
    # Get dnsmasq if needed
    get_dnsmasq()
    
    inet_iface = args.inet_iface
    ap_iface = args.ap_iface
    essid = args.essid
    channel = args.channel
    interfaces = [inet_iface, ap_iface]

    # reset interfaces
    reset_interfaces(interfaces)

    # Set iptable rules and kernel variables.
    Popen(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', str(inet_iface), '-j', 'MASQUERADE'], stdout=DN, stderr=PIPE)
    Popen(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=DN, stderr=PIPE)

    print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'

    # Start AP
    dhcpconf = dhcp_conf(ap_iface)
    dhcp(dhcpconf, ap_iface)
    start_ap(ap_iface, channel, essid, args)
    os.system('clear')
    print '[' + T + '*' + W + '] ' + T + \
          essid + W + ' set up on channel ' + \
          T + channel + W + ' via ' + T + ap_iface \
          + W + ' on ' + T + str(ap_iface) + W

    # Main loop.
    try:
        while 1:
            os.system("clear")
            print "DHCP Leases: "
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                proc = check_output(['cat', '/var/lib/misc/dnsmasq.leases'])
                lines = proc.split('\n')
                lines += ["\n"] * (5 - len(lines))
            else:
                lines = ["\n"] * 5
            time.sleep(1.5)
    except KeyboardInterrupt:
        shutdown(interfaces)
