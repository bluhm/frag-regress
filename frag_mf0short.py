#!/usr/local/bin/python2.7

print "ping fragment without MF that overlaps the last fragment at beginning"

#           |---------|
#      |XXXXXXXXX|
# |---------|

import os
from addr import *
from scapy.all import *

pid=os.getpid()
eid=pid & 0xffff
payload="ABCDEFGHIJKLMNOPQRSTUVWX"
dummy="0123456701234567"
packet=IP(src=LOCAL_ADDR, dst=REMOTE_ADDR)/ \
    ICMP(type='echo-request', id=eid)/payload
frag=[]
fid=pid & 0xffff
frag.append(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR, proto=1, id=fid, frag=2)/ \
    str(packet)[36:52])
frag.append(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR, proto=1, id=fid, frag=1)/ \
    dummy)
frag.append(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR, proto=1, id=fid, flags='MF')/ \
    str(packet)[20:36])
eth=[]
for f in frag:
	eth.append(Ether(src=LOCAL_MAC, dst=REMOTE_MAC)/f)

if os.fork() == 0:
	time.sleep(1)
	sendp(eth, iface=LOCAL_IF)
	os._exit(0)

ans=sniff(iface=LOCAL_IF, timeout=3, filter=
    "ip and src "+REMOTE_ADDR+" and dst "+LOCAL_ADDR+" and icmp")
for a in ans:
	if a and a.type == ETH_P_IP and \
	    a.payload.proto == 1 and \
	    a.payload.frag == 0 and a.payload.flags == 0 and \
	    icmptypes[a.payload.payload.type] == 'echo-reply':
		id=a.payload.payload.id
		print "id=%#x" % (id)
		if id != eid:
			print "WRONG ECHO REPLY ID"
			exit(2)
		load=a.payload.payload.payload.load
		print "payload=%s" % (load)
		if load == payload:
			exit(0)
		print "PAYLOAD!=%s" % (payload)
		exit(1)
print "NO ECHO REPLY"
exit(2)
