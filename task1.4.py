from scapy.all import *

def spoofer(pkt):

    if (pkt[ICMP].type == 8):
        dst=pkt[IP].dst
        src=pkt[IP].src
        seq = pkt[ICMP].seq
        id = pkt[ICMP].id
        load=pkt[Raw].load
        spoof = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load

        send(spoof)

if __name__=="__main__":
    
    sniff(iface="br-78035c09e487", filter="icmp", prn=spoofer)
