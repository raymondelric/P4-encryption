#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface
'''
class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
'''
class Payload(Packet):
    fields_desc = [IntField("data", None), IntField("encrypt", None), IntField("type", None), IntField("index", None)]

bind_layers(TCP, Payload, dport=1234)


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print "got a packet"
        hexdump(pkt)
        pkt.show()
        print(pkt.summary())
        sys.stdout.flush()
        #s = pkt[Raw].load[0:4]#[:len(pkt[Raw].load)//2]
        #print(pkt[Payload].data - 12345)
	#print(str(s))
        #tmp = s.split('\x')
	#print(tmp)
        #s = "0x" + ''.join(tmp)
        #print(pkt[Payload].encrypt)


def main():
    '''ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))'''
    iface = get_if()
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
