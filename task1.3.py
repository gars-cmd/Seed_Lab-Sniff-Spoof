
from scapy.all import *

i = 0
a = IP()
a.dst = '8.8.8.8'
b = ICMP()
p=None
a.ttl = 1
while(p==None):
    p = sr1(a/b)
    print(i)
    i+=1
    a.ttl = i
    
    

