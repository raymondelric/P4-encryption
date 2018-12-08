#!/usr/bin/env python
'''
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
'''

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, TCP, UDP
from scapy.fields import *
import readline



def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class Payload(Packet):
	fields_desc = [ IntField("data", int(sys.argv[2])), IntField("encrypt", 1), IntField("type", int(sys.argv[3])), IntField("index", int(sys.argv[4]))]

bind_layers(TCP, Payload, dport=1234)

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])        

    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) 
    pkt = pkt / TCP(dport=1234, sport=random.randint(12345,54321)) 
    pkt = pkt / Payload()
    hexdump(pkt)
    pkt.show()
    print(pkt.summary())
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
