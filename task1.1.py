

from scapy.all import *

print("#########start the sniffing process#########")

def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface=['br-78035c09e487','br-8c97b7e01341'],filter='icmp',prn=print_pkt)  
# pkt = sniff(iface=['br-78035c09e487','br-8c97b7e01341'],filter='tcp && src host 10.9.0.6 && dst port 23',prn=print_pkt) TASK1.1B
# pkt = sniff(iface=['br-78035c09e487','br-8c97b7e01341'],filter='src net 10.9.0.0/24 ',prn=print_pkt) TASK1.C
