#!/usr/bin/python


import socket
# from socket import *
# import re
from struct import *


## http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm



class DNSquery:
	qtypeCodes = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT"}

	opCodes = {0: "Std Query", 2: "Status", 4: "Notify", 5: "Update"}


	def __init__(self, query):

		self.query_header = query[:12]
		self.query_id, = unpack('!H', self.query_header[:2] )
		print "CLASS: query_id: ", self.query_id

		self.query_byte_3 = self.query_header[2:3]
		self.query_byte_3, = unpack('!B', self.query_byte_3)
		## set response flag ON
		# self.response = self.query_byte_3 ^ 128
		print "CLASS: byte 3 w/ query/response flag:", format(self.query_byte_3, '08b')
		# , \
		#	" derived from: ", format(self.query_byte_3, '08b')
		# self.query_byte_3 = self.response

		self.query_byte_4 = self.query_header[3:4]
		self.query_byte_4, = unpack('!B', self.query_byte_4)
		print "CLASS: byte 4 w/ recursion flag:", format(self.query_byte_4, '08b')

		self.question_count = self.query_header[4:6]
		self.question_count, = unpack('!H', self.question_count)
		print "CLASS: question_count: ", self.question_count

		self.answer_count = self.query_header[6:8]
		self.answer_count, = unpack('!H', self.answer_count)
		print "CLASS: answer_count: ", self.answer_count

		self.auth_rec_count = self.query_header[8:10]
		self.auth_rec_count, = unpack('!H', self.auth_rec_count)
		print "CLASS: auth_rec_count: ", self.auth_rec_count

		self.addl_rec_count = self.query_header[10:12]
		self.addl_rec_count, = unpack('!H', self.addl_rec_count)
		print "CLASS: addl_rec_count: ", self.addl_rec_count

		## Question section ends with NULL (\x00):
		## re-code to iterate through bytes until it's found!
		## Stick name parts into array, could be > 2, i.e.
		## www.ronaldbarnes.ca
		##
		self.questionName = data[12:]
		print "questionName: \"%s\"" % repr(self.questionName)
		name1len, = unpack('B', self.questionName[0:1])
		self.name1 = self.questionName[1:name1len + 1]
		print "name1len: %d  name1: \"%s\"" % (name1len, self.name1)

		name2len, = unpack('B', self.questionName[name1len+1:name1len+2])
		self.name2 = self.questionName[name2len + 2:name2len + 2 + name2len]
		print "name2len: %d  name2: \"%s\"" % (name2len, self.name2)
		self.nullByte, = unpack('b', '\x00')

		QType = self.questionName[name1len + name2len + 3:name1len + name2len + 3 + 2]
		QClass = self.questionName[name1len + name2len + 3 + 2:name1len + name2len + 3 + 2 + 2]
		print "QType (A vs MX): ", self.qtypeCodes[ unpack('!H', QType)[0]], " QClass (IN=1): ", unpack('!H', QClass)[0]

		self.questionName = self.questionName[:name2len * 2 + 3 +4]
		print "questionName TRIMMED (len: %d): \"%s\"" % (len(self.questionName), repr(self.questionName) )


	def questionName(self):
		return self.questionName

	def setResponseFlag(self):
		print "Response flag set: from: ", format(self.query_byte_3, '08b'),
		self.query_byte_3 = self.query_byte_3 ^ 128
		print " to: ", format(self.query_byte_3, '08b')

	def recursionOff(self):
		self.query_byte_4 = self.query_byte_4 ^ 128

	def addAnswer(self):
		self.answer_count = self.answer_count + 1
		print "CLASS: NEW answer_count: ", self.answer_count

	def addAdditional(self):
		self.addl_rec_count = self.addl_rec_count + 1
		print "CLASS: NEW additional_count: ", self.answer_count

	def subAdditional(self):
		self.addl_rec_count = self.addl_rec_count - 1
		if self.addl_rec_count < 0:
			self.addl_rec_count = 0
		print "CLASS: NEW additional_count: ", self.addl_rec_count

	def addAuth(self):
		self.auth_rec_count = self.auth_rec_count + 1
		print "CLASS: NEW auth_rec_count: ", self.auth_rec_count

	def subAuth(self):
		self.auth_rec_count = self.auth_rec_count - 1
		if self.auth_rec_count < 0:
			self.auth_rec_count = 0
		print "CLASS: NEW auth_rec_count: ", self.auth_rec_count

	def printHeader(self):
		print( "HEADER: \"%x%x%x%x%x%x%x\"" % (self.query_id \
			, self.query_byte_3 \
			, self.query_byte_4 \
			, self.question_count \
			, self.answer_count \
			, self.auth_rec_count \
			, self.addl_rec_count \
			))
		print "Length header: ", len(xyz)

	def getHeader(self):
		xyz = pack( "!HBBHHHH", self.query_id \
			, self.query_byte_3 \
			, self.query_byte_4 \
			, self.question_count \
			, self.answer_count \
			, self.auth_rec_count \
			, self.addl_rec_count \
			)
		return xyz

	##  HUH? AUTO-COMPLETE GAVE THIS:
	## def t_DNSMessageHeaderandQuestionSectionFormat
	def questionSection(self):
		return self.questionName


class DNSResponse(DNSquery):
	def __init__(self):
		print "DNSResponse CLASS!"




## #######################################################

IP_ADDR = '127.0.0.1'
IP_PORT = 53
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.settimeout(5)
s.bind(( IP_ADDR, IP_PORT))
print("Bound to address %s :: %s " % (IP_ADDR, IP_PORT) );
# s.listen(1)
# print "Listening on port ", IP_PORT


#try:
#	conn, addr = s.accept()
#	print 'Connection accepted from address:', addr
#except socket.timeout:
#	print "Timeout on socket..."
#	# conn.shutdown(2)	## 0: rec, 1: tx, 2: both
#	# conn.close()
#	raise SystemExit

while(True):
	## data = conn.recv(BUFFER_SIZE)
	data, client_ip_port = s.recvfrom(BUFFER_SIZE)
	client_ip, client_port = (client_ip_port)
	if not data: break
	# data = data.rstrip('\r\n')
	## ##############################################################################
	## Header format (12 bytes)
	##
	## http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
	##
	## ID: 2 bytes, return to client for query q&a matching
	## First byte:
	##	bit 1: QR Query/Response flag: 0: query, 1: response
	##	bit 2-5: Opcode: 0=std query, 2=srv status req.
	##	bit 6: Authoritative Answer Flag: 1=yes, 0=no
	##	bit 7: Truncation Flag: 1=yes, 0=no: UDP max 512 bytes
	##	bit 8: Recursion Desired: return unchanged
	## Second byte:
	##	bit 1: RA Recursion Available: yes=1
	##	bit 2-4: Zero (reserved bits)
	##	bit 5-8: RCode: 0 = No Error, 1=fmt err, 2=srv fail, 
	##		3=name err, 4=unused, 5=refused, ... 9=not auth
	## QDCount Question count: 2 bytes
	## AN Count Answer count: 2 bytes
	## NS Count: Authority Record count: 2 bytes
	## AR Count: Additional Record count: 2 bytes


	query_header = data[:12]
	query_id = query_header[:2]
	query_byte_3 = query_header[2:3]

	print("received data: client_ip: %s, %i bytes\nheader: \"%s\"" % (client_ip, len(data), repr(query_header) ) )
#	print("Received query data: \"%s\"" % repr(data) )


	x = DNSquery(data)
	y = DNSResponse()
	x.setResponseFlag()
	x.recursionOff()
	x.addAnswer()
	x.subAdditional()
	x.subAuth()

	zzz = x.getHeader()
	# print "RETURN HEADER: \"", zzz, "\""





	print '\n###\n' \
	+ repr(pack('!b', 2) + 'my' + pack('!b', 2) + 'ip' \
	+ pack('!b', 0) \
	+ pack('!HHih', 1,1,34,4) \
	+ pack('!iiii', 127,0,0,1) )
	
	s.sendto(x.getHeader() \
	+ x.questionSection() \
	+ pack('!B', 2) + 'my' + pack('!B', 2) + 'ip' + pack('!B', 0) \
	+ pack('!HHiH', 1,1,34,4) 
	+ pack('BBBB', 127,0,0,1), client_ip_port)

#	s.sendto(x.header() + "2" + "my" + pack('b', 2) + "ip" + pack('b', 0) + "1112349" + client_ip, client_ip_port)
#	s.sendto(x.header(), client_ip_port)


	raise SystemExit  ## aka: sys.exit but without import sys


