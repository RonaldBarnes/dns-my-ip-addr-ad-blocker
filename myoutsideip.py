#!/usr/bin/python


import socket
import re


TCP_IP = '127.0.0.1'
TCP_PORT = 53
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(15)
s.bind(( TCP_IP, TCP_PORT))
s.listen(1)
print "Listening on port ", TCP_PORT


conn, addr = s.accept()
print 'Connection address:', addr

while(True):
	try:
		data = conn.recv(BUFFER_SIZE)
		if not data: break
		data = data.rstrip('\r\n')
		print("received data: \"%s\"" % data )
		match = re.search(r'^(\w+)', data)
		if match.group(0) == 'quit':
##		if "quit" in data.lower():

##		print( "Exiting per client command: ", data, "...", match.group(0) )
			print( "Exiting per client command: \"%s\" ... %s" % (data, match.group(0) ) )
			conn.shutdown(2)	## 0: rec, 1: tx, 2: both
			conn.close()
			raise SystemExit  ## aka: sys.exit but without import sys
			 #break #exit #quit
	except socket.timeout:
		print "Timeout on socket..."
		conn.shutdown(2)	## 0: rec, 1: tx, 2: both
		conn.close()
		raise SystemExit
	conn.send(data + "\n\r")	## echo data back to client
conn.close()

