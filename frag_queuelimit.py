#!/usr/local/bin/python2.7

print "drop extra long fragment queue"

# |----|
#      |----|
#           |----|
#                 ...                                           ...
#                                                                  |----|

import os
from addr import *
from scapy.all import *

pid=os.getpid()
eid=pid & 0xffff
fid=pid & 0xffff
payload=80*"ABCDEFGHIJKLMNOP"

frag=[]
# send packets with 64 and 65 fragments
for max in (63, 64):
	eid = ~eid & 0xffff
	fid = ~fid & 0xffff
	packet=IP(src=LOCAL_ADDR, dst=REMOTE_ADDR)/ \
	    ICMP(type='echo-request', id=eid)/payload
	for i in range(max):
		frag.append(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR, proto=1,
		    id=fid, frag=i, flags='MF')/str(packet)[20+i*8:28+i*8])
	frag.append(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR, proto=1,
	    id=fid, frag=max)/str(packet)[20+8*max:])
eth=[]
for f in frag:
	eth.append(Ether(src=LOCAL_MAC, dst=REMOTE_MAC)/f)

if os.fork() == 0:
	time.sleep(1)
	for e in eth:
		sendp(e, iface=LOCAL_IF)
	os._exit(0)

reply=False
ans=sniff(iface=LOCAL_IF, timeout=3, filter=
    "ip and src "+REMOTE_ADDR+" and dst "+LOCAL_ADDR+" and icmp")
for a in ans:
	if a and a.type == ETH_P_IP and \
	    a.payload.proto == 1 and \
	    a.payload.frag == 0 and a.payload.flags == 0 and \
	    icmptypes[a.payload.payload.type] == 'echo-reply':
		id=a.payload.payload.id
		print "id=%#x" % (id)
		if id == eid:
			print "ECHO REPLY FROM 65 FRAGMENTS"
			exit(1)
		if id != ~eid & 0xffff:
			print "WRONG ECHO REPLY ID"
		data=a.payload.payload.payload.load
		print "payload=%s" % (data)
		if data != payload:
			print "PAYLOAD!=%s" % (payload)
			exit(2)
		reply=True
if not reply:
	print "NO ECHO REPLY FROM 64 FRAGMENTS"
	exit(2)
exit(0)
