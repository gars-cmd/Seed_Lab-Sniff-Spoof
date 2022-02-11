
from scapy.all import *

a = IP()
a.dst = '10.0.9.8'
b = ICMP()
p = a/b
send(p)