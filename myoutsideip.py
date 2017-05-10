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


		## Question section ends with NULL (\x00) and has binary length
		## bytes, so 0x03 would indicate next part is "www", for example:
		##
		self.questionName = data[12:]
		## print "questionName: \"%s\"" % repr(self.questionName)

		## Parse out "question name" i.e. domain for which info requested:
		self.QNames = []
		kounterNameParts = 0
		offsetNamePart = 0
		lenNamePart = 1
		while(self.questionName[offsetNamePart:lenNamePart] != pack('B', 0) ):
			## Get byte that indicates (in binary) length of next name part:
			lenNamePart, = unpack('B', self.questionName[offsetNamePart:lenNamePart])
			## Move pointers along the "question" to extract name part (i.e. www or google):
			offsetNamePart += 1
			lenNamePart += offsetNamePart
			kounterNameParts += 1
			## extract a name part:
			self.QNames.append( self.questionName[offsetNamePart:lenNamePart] )
#			print "NAME PART #", kounterNameParts, 
#			print " from: ", offsetNamePart, " to: ", lenNamePart, 
#			print " is: ", self.QNames
			offsetNamePart = lenNamePart
			lenNamePart += 1
#			print "NEXT BYTE: ", repr(self.questionName[offsetNamePart:lenNamePart])
#			if self.questionName[offsetNamePart:lenNamePart] == pack('B', 0):
				## print "Question for ", ".".join(self.QNames)
#				break

		## QType is "A", "MX", "CNAME", ... 2 bytes used:
		offsetNamePart += 1
		lenNamePart += 2
		self.QType = self.questionName[offsetNamePart:lenNamePart]
		## QClass is "IN" in 99.999% of cases:
		
		offsetNamePart += 2
		lenNamePart += 2
		self.QClass = self.questionName[offsetNamePart:lenNamePart]
		print "QType (A vs MX): ", self.qtypeCodes[ unpack('!H', self.QType)[0]], " QClass (IN=1): ", unpack('!H', self.QClass)[0]

		self.questionName = self.questionName[:lenNamePart]
		print "questionName TRIMMED (len: %d): \"%s\"" % (len(self.questionName), repr(self.questionName) )


	def questionName(self):
		## Return question to client:
		return self.questionName

	def getQuestionNameCanonical(self):
		## Return READABLE question name for logging
		## The binary lengths stripped, separators of "." added
		return ".".join(self.QNames)

	def getQNames(self):
		return self.QNames


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

	def NXDOMAIN(self):
		print "CLASS: NXDOMAIN before:", self.query_byte_4,
		self.query_byte_4 = self.query_byte_4 ^ 3
		print "CLASS: NXDOMAIN after:", self.query_byte_4


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
	def __init__(self,QNames):
#		print "DNSResponse CLASS!"
		print "Qnames:", QNames

	def getResourceRecord(self, QNames, QType, QClass, QTTL, QAnswer):
#		print "getResourceRecord! ==========================="
#		print "Qnames:", QNames
		print "QType:", repr(QType), " QClass:", repr(QClass)
#		print "QAnswer:", repr(QAnswer)
		returnString = ''
		for oneName in QNames:
			lenName = len(oneName)
#			print "One NAME: %s  and length: %d" % (oneName, lenName)
			returnString += pack("!B", lenName)
			returnString += oneName
		returnString += pack("!B", 0)
		returnString += QType + QClass
		returnString += pack("!i", QTTL)

		## MX records get a 2-byte Preference value first:
		if unpack('!H', QType)[0] == 15:
			## Answer is NOT 4 octets of IP address but domain name in STD DNS 
			## NAME format, with length bytes preceding each portion, and
			## trailing NULL byte.
			## ALSO, preceding all that is 2-byte Preference value which must
			## be included in field length indicator
			returnString += str(pack("!H", len('.'.join(QNames)) + 2 + 2 ) )
			print "QType == MX, adding additional field to RR:", repr(QType)
			returnString += pack('!H', 1)  ## Arbitrary Preference value = 1
			for oneName in QNames:
				lenName = len(oneName)
				print "One NAME: %s  and length: %d" % (oneName, lenName)
				returnString += pack("!B", lenName)
				returnString += oneName
			returnString += pack("!B", 0)
		else:
			returnString += pack("!H", 4)
			for octet in QAnswer.split('.'):
	#			print "OCTET:", octet
				returnString += pack("!B", int(octet) )
		print "RESOURCE RECORD RETURN len: %d  and VALUE: %s" % (len(returnString), repr(returnString))
		return returnString





## #######################################################

IP_ADDR = '127.0.0.1'
IP_PORT = 53
BUFFER_SIZE = 512

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
#	x.NXDOMAIN()
	x.setResponseFlag()
	x.recursionOff()
	x.addAnswer()
	x.subAdditional()
	x.subAuth()

	y = DNSResponse(x.getQNames() )
	# y.getResourceRecord(x.getQNames(), x.QType, x.QClass, 0, client_ip)

	zzz = x.getHeader()
	# print "RETURN HEADER: \"", zzz, "\""
	print "Question is for:", x.getQuestionNameCanonical()





	retval = x.getHeader() \
	+ x.questionSection() \
	+ y.getResourceRecord(x.getQNames(), x.QType, x.QClass, 1234, client_ip)

#	print "RETVAL1: len: %d  value: %s" % (len(retval), repr(retval))

	s.sendto(retval, client_ip_port)

	raise SystemExit  ## aka: sys.exit but without import sys


	print '\n###\n' \
	+ repr(pack('!B', 2) + 'my' + pack('!B', 2) + 'ip' \
	+ pack('!B', 0) \
	+ pack('!HHiH', 1,1,34,4) \
	+ pack('!BBBB', 127,0,0,1) )


	retval = x.getHeader() \
	+ x.questionSection() \
	+ pack('!B', 2) + 'my' + pack('!B', 2) + 'ip' + pack('!B', 3) + 'com' + pack('!B', 2) + 'uk' + pack('!B', 0) \
	+ pack('!HHiH', 1,1,1234,4) \
	+ pack('BBBB', 127,0,0,1)
	print "RETVAL2: len: %d  value: %s" % (len(retval), repr(retval))



	s.sendto(x.getHeader() \
	+ x.questionSection() \
	+ pack('!B', 2) + 'my' + pack('!B', 2) + 'ip' + pack('!B', 0) \
	+ pack('!HHiH', 1,1,1234,4) \
	+ pack('BBBB', 127,0,0,1), client_ip_port)


	s.sendto(retval, client_ip_port)

	s.sendto(x.getHeader() \
	+ x.questionSection() \
	+ y.getResourceRecord(x.getQNames(), x.QType, x.QClass, 34, client_ip) \
	, client_ip_port)







