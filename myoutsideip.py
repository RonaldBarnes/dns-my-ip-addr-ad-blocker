#!/usr/bin/python

"""
BlackHoleDNS:

Return domain not found (NXDOMAIN) for sites included in
the appropriate file (trackers, ad servers, etc.).

Also supports handy WAN-side IP address identification via
	dig my.ip @[server]
This replicates the myoutsideip.net service that's gone offline.

Recursion is NOT supported, so have a secondary DNS setting
in your router if this is primary DNS server.
"""


import socket
# from socket import *
from struct import *
from sys import argv, exc_info
import re
from os import stat
from threading import Thread
from SocketServer import ThreadingMixIn
import time

## print "ARGV: %r,  len ARGV: %d" % (argv, len(argv))


## print "strftime:", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime() )


## Identical (in this invocation) to ctime() (hate it...)
## print "asctime:", time.asctime()
##
## I hate, Hate, HATE ctime(): "Sun Jul  2 20:34:55 2017"
## print "ctime:", time.ctime()


## raise SystemExit




## http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
## https://docs.python.org/2/library/socketserver.html#socketserver-udpserver-example

IP_ADDR = '127.0.0.1'		## for localhost testing
IP_ADDR = '0.0.0.0'
IP_PORT = 53535				## for localhost testing
IP_PORT = 53
BUFFER_SIZE = 512

CONFDIR = '/etc/BlackHoleDNS'
verbosityGlobal = 2
NXDOMAINfileTimestamp = 0
## change log file default name to something sane, please?
logFile = '/var/log/BlackHoleDNS.log'




## #######################################################

def parseArgs(keywords):
	"""
	Handle command line arguments by setting appropriate values
	"""
	#print "keywords: %r,  len keywords: %d" % (keywords, len(keywords))
	for oneWord in keywords:
		match = None
		match = re.match('(--debug)[=:](.+)', oneWord)
		if match and len(match.groups() ) == 2:
			#print "KEYWORD:", match.group(1), " VALUE:", match.group(2)
			global verbosityGlobal
			verbosityGlobal = int(match.group(2) )
			print match.group(1), verbosityGlobal
			continue
		match = re.search('(--conf(?:ig)*(?:-dir)*)[=:](.+)', oneWord)
		if match and len(match.groups() ) >= 2:
			# print "KEYWORD:", match.group(1), " VALUE:", match.group(2)
			global CONFDIR
			CONFDIR = match.group(2)
			print match.group(1), CONFDIR
			continue
		match = re.search('(--log)-?(?:file)*[=:](.+)', oneWord)
		if match and len(match.groups() ) >= 2:
			#print "KEYWORD:", match.group(1), " VALUE:", match.group(2)
			global logFile
			logFile = match.group(2)
			print match.group(1), logFile
			continue
		if match == None:
			print "\nWARNING: Unrecognized argument: ", oneWord
			raise SystemExit


## Parse command line arguments if given (argv[0] is script name):
if (len(argv) > 1):
	args = argv[1:]
	## print "ARGS: %r,  len ARGS: %d" % (args, len(args))
	parseArgs( argv[1:] )



## Compose location of the list of NXDOMAINs from user-overridable options:
NXDOMAINfile = re.sub('//', '/', CONFDIR + '/NXDOMAIN.list' )






## #######################################################

def loadNXDOMAINfile():
	"""
	Load the file of domains to "black-hole", i.e. give not-found
	message for (aka NXDOMAIN)
	"""
	global NXDOMAINs
	global NXDOMAINfile

	## Get the timestamp of that file, may check it for changes and
	## auto-reload it:
	try:
		global NXDOMAINfileTimestamp
		NXDOMAINfileTimestamp = stat(NXDOMAINfile).st_mtime
		NXDOMAINs = open(NXDOMAINfile, 'r').read().splitlines()
	except:
		print "ERROR:", exc_info()[1]
		raise SystemExit


	## Remove comments:
	## print "LEN NXDOMAINs:", len(NXDOMAINs)

	index = 0

	while index < len(NXDOMAINs):
		NXDOMAINs[index] = re.sub('[\t ]*#+.*$','', \
			NXDOMAINs[index] ).lower()
#		if index < 10:
#			print "%03d \"%s\"" % (index+1, NXDOMAINs[index] )
		if NXDOMAINs[index][0:1] == 'X'  or  len(NXDOMAINs[index]) == 0:
			# print "%03d \"%s\"  DELETING..." % (index+1, NXDOMAINs[index] )
			del NXDOMAINs[index]
		else:
			index += 1
	## print "LEN NXDOMAINs without comments:", len(NXDOMAINs)


loadNXDOMAINfile()


## Open log file
try:
	logFH = open(logFile, 'ab')	## append, binary (unlikely useful)
	print "Opened log file %s" % logFile
except:
	print "ERROR:", exc_info()[1]
	raise SystemExit


## raise SystemExit









## #######################################################

## A logging utility for debugging messages. NOT for logging
## queries to a log file.
##
## This requires some disambiguation...
##
## Accepts 2 forms of parameters; mutually exclusive:
##
## debugMessage('A message', 4)
## or
## debugMessage(msg='A message', verb=4)
## 
## The second format is handy when expanding functionality at
## later date.
##
## Note that both methods do not work in same invocation
##
## Logging default level is 2 (4 is a lot, 0 is nearly nothing):
## See verbosityGlobal variable above for its initialization.

##def debugMessage(message, *positional_parameters, **keyword_parameters):
def debugMessage(msgBare = None, verbBare = None, **keywords):
	"""
	All logging in central location, with customizable
	verbosity setting (via --debug=[0-4] as startup argument.
	"""
	verbosityLocal = None
	global verbosityGlobal


	if ('msg' in keywords):
		msg = keywords['msg']
		# print 'MESSAGE: ', msg
	elif (msgBare == None):
		print 'NO MESSAGE...'
		return
	else:
		msg = msgBare

	if ('verb' in keywords):
		verbosityLocal = keywords['verb']
		# print 'VERB: ', verbosityLocal
	elif (verbBare == None):
		verbosityLocal = verbosityGlobal
	else:
		verbosityLocal = verbBare

	if verbosityLocal <= verbosityGlobal:
		print "(*) %s" % msg










## #######################################################

class ClientThread(Thread):

	def __init__(self, ip, port):
		Thread.__init__(self)
		self.ip = ip
		self.port = port
		debugMessage(msg="[+] New thread started for "+ip+":"+str(port)
			 + ' -------------------------------',
			 verb=2)

	def run(self):
		## print "ClientThread()"
		debugMessage(msg=format("Connection: client_ip: %s, %i bytes" 
						% (client_ip, len(data) ) ) , verb=1)

		debugMessage(msg="Received query data: " + repr(data), verb=4 )


		## Build a query object, set response flag, etc:
		oneQuery = DNSquery(data)
		oneQuery.setResponseFlag()
		oneQuery.setRecursionOff()


		query_domain = oneQuery.getQuestionNameCanonical().lower()
		debugMessage( msg="Question is for: " + query_domain,
			verb=1)

		## Check for a black-holed domain name:
		nxdomainFound = False
		for domain in NXDOMAINs:
			## print "DOMAIN being tested:", domain
			if query_domain.endswith(domain ):
				debugMessage( msg='NXDOMAIN match: ' + domain, verb=2)
				oneQuery.NXDOMAIN()
				oneQuery.subAnswer()
				nxdomainFound = True
				break


		"""
		Black holes get NXDOMAIN, "my.ip" gets real reply,
		possibly-valid but unknown domains get SERVFAIL,
		 i.e. "don't know"
		"""
		if not nxdomainFound:
			if query_domain[0:5] == 'my.ip':
				## True when looking for WAN-side IP via:
				## dig my.ip @[this-server]
				## Replicates dig my.ip @outsideip.net
				oneQuery.ResourceRec.append( \
					oneQuery.createResourceRecord(oneQuery.QNames, \
					oneQuery.QType, oneQuery.QClass, 0, client_ip))
				oneQuery.addAnswer()

				## Add a boastful TXT RR, because why not?
				oneQuery.ResourceRec.append( \
					oneQuery.createResourceRecord(oneQuery.QNames, \
					pack('!H', 16), \
					oneQuery.QClass, 86400, \
					['(c)', 'Ronald Barnes', '2017'] ))
				oneQuery.addAdditional()
			else:
				## Standard reply for non-recursive "Not Found"
				## Test this via: dig cbc.ca @8.8.8.8 +norecurse
				oneQuery.SERVFAIL()


		debugMessage(msg=format("oneQuery.ResourceRec: %r"
			% oneQuery.ResourceRec), verb=4)

		retval = oneQuery.getHeader() \
		+ oneQuery.questionName \
		+ ''.join(oneQuery.ResourceRec)  \


		s.sendto(retval, (client_ip, client_port)) # client_ip_port)


		## This goes to log file:

#		logFH.writelines( time.strftime('%Y-%m-%d %H:%M:%S', \
#			time.localtime() ), client_ip, query_domain, nxdomainFound )
#		print >> logFile (time.strftime('%Y-%m-%d %H:%M:%S', \
#			time.localtime() ), client_ip, query_domain, nxdomainFound )
		print >> logFH, time.strftime('%Y-%m-%d %H:%M:%S', \
			time.localtime() ), client_ip, query_domain, nxdomainFound

		logFH.flush()






## #######################################################

class DNSquery:
	"""
	Turn DNS query into object, manipulate flag fields/bits,
	set status flags/bits, compose appropriate ResourceRecord
	for reply.
	"""
	## Type "A" is only one relevant to "dig my.ip", others may be
	## implemented if need arises.  This is a subset of possiblities.
	qtypeCodes = {1: "A", 2: "NS",
		5: "CNAME", 6: "SOA",
		10: 'NULL',11: 'WKS', 
		12: "PTR", 13: "HINFO",
		15: "MX", 16: "TXT", 
		33: 'SRV', 'AFXR': 252,
		255: 'ANY'}

	## Types of queries (a subset): only 0: Standard Query is implemented:
	opCodes = {0: "Std Query", 2: "Status", 4: "Notify", 5: "Update"}

	def __init__(self, query):

		## An array of Resource Records that may be returned to client:
		self.ResourceRec = []
		del self.ResourceRec[0:]

		## Header gets rebuilt with some bits fiddled:
		## Retrieve it with getHeader()
		self.query_header = query[:12]
		self.query_id, = unpack('!H', self.query_header[:2] )
		debugMessage( msg="QueryID: " + str(self.query_id), verb=2)

		## Byte 3 of header contains question / response bit
		self.query_byte_3 = self.query_header[2:3]
		self.query_byte_3, = unpack('!B', self.query_byte_3)
		## set response flag ON
		# self.response = self.query_byte_3 ^ 128
		debugMessage( msg="byte 3 w/ query/response flag:" +
			 format(self.query_byte_3, '08b'), verb=3)

		## Byte 4 of header contains RCode / error code and
		## recursion flag:
		self.query_byte_4 = self.query_header[3:4]
		self.query_byte_4, = unpack('!B', self.query_byte_4)
		debugMessage(msg="byte 4 w/ recursion flag: "
			 + format(self.query_byte_4, '08b'), verb=3)

		## Only intending to handle one question regardless of count
		self.question_count = self.query_header[4:6]
		self.question_count, = unpack('!H', self.question_count)
		debugMessage(msg="question_count: " 
			 + str(self.question_count), verb=3)

		## Answer count will be 1 in most / all cases
		self.answer_count = self.query_header[6:8]
		self.answer_count, = unpack('!H', self.answer_count)
		debugMessage(msg="answer_count: " 
			 + str(self.answer_count), verb=4)

		## Unlikely to add auth records, ought to always be zero
		self.auth_rec_count = self.query_header[8:10]
		self.auth_rec_count, = unpack('!H', self.auth_rec_count)
		debugMessage(msg="auth_rec_count: "
			 + str(self.auth_rec_count), verb=4)

		## May have additional records for TXT or ANY type queries,
		## or for adding fancy (c) notices
		self.addl_rec_count = self.query_header[10:12]
		self.addl_rec_count, = unpack('!H', self.addl_rec_count)
		debugMessage(msg="Received query's addl_rec_count: "
			 + str(self.addl_rec_count), verb=2)
		##
		## NOTE: "dig" has this set to 1 addl record, and most 
		## servers send it back unchanged, without an addl record
		if (self.addl_rec_count == 1):
			self.subAdditional()


		## Question section indicates the domain inquired about.
		## It ends with NULL (\x00) and has binary length bytes,
		## so 0x03 would indicate next part is "www", for example:
		##
		self.questionName = data[12:]
		## debugMessage(msg="questionName: \"%s\"" \
		##		% repr(self.questionName), verb=4)

		## Parse out "question name" minus length bytes & NULL
		## i.e. domain for which info requested:
		self.QNames = None
		self.QNames = []
		del self.QNames[0:]
		kounterNameParts = 0
		offsetNamePart = 0
		lenNamePart = 1
		## Cycle through QuestionName until trailing NULL found:
		while(self.questionName[offsetNamePart:lenNamePart] \
			!= pack('B', 0) ):

			## Get byte that indicates (in binary) the
			## length of next name part:
			lenNamePart, = unpack('B', \
				self.questionName[offsetNamePart:lenNamePart])
			## Move pointers along the "question" to
			## extract name part (i.e. www or google):
			offsetNamePart += 1
			lenNamePart += offsetNamePart
			kounterNameParts += 1
			## extract a name part:
			self.QNames.append( \
				self.questionName[offsetNamePart:lenNamePart] )
#			print "NAME PART #", kounterNameParts, 
#			print " from: ", offsetNamePart, " to: ", lenNamePart, 
			debugMessage(msg= "QNAMES is: " + str(self.QNames ), verb=3)
			offsetNamePart = lenNamePart
			lenNamePart += 1


		## QType is "A", "MX", "CNAME", ... 2 bytes used:
		offsetNamePart += 1
		lenNamePart += 2
		self.QType = self.questionName[offsetNamePart:lenNamePart]

		## QClass is "IN" in 99.999% of cases:
		offsetNamePart += 2
		lenNamePart += 2
		self.QClass = self.questionName[offsetNamePart:lenNamePart]
		debugMessage(msg="QType (A vs MX): " 
			 + self.qtypeCodes[ unpack('!H', self.QType)[0]]
			 + " (code %d)" % unpack('!H', self.QType)[0]
			 , verb=2)

		debugMessage( "QClass (IN=1): ", unpack('!H', self.QClass)[0],
			 verb=4)

		self.questionName = self.questionName[:lenNamePart]
		debugMessage(msg=format("questionName TRIMMED (len: %d): \"%s\"" %
			 (len(self.questionName), repr(self.questionName) ) ),
			 verb=3)




	def getQuestionNameCanonical(self):
		"""
		Return human-readable "question name" (domain) for logging, etc.
		The binary lengths stripped, separators of "." added.
		"""
		return ".".join(self.QNames)

#	def getQNames(self):
#		debugMessage(msg=format("getQNames() returning: %r" % self.QNames),
#			 verb=4)
#		return self.QNames


	def setResponseFlag(self):
		self.query_byte_3 = self.query_header[2:3]
		self.query_byte_3, = unpack('!B', self.query_header[2:3])
		## set response flag ON
		# self.response = self.query_byte_3 ^ 128
##		print "Response flag set: from: ", format(self.query_byte_3, '08b'),
		self.query_byte_3 = self.query_byte_3 ^ 128
#		self.query_header = self.query_header[:2] \
#			+ pack('!B', self.query_byte_3) \
#			+ self.query_header[4:]
		## ERROR on substring assignment:
		## self.query_header[2:3] = pack('!16', unpack('!B', self.query_header[2:3])[0] ^ 128)
##		print " to: ", format(self.query_byte_3, '08b')
		debugMessage( msg="byte 3 w/ query/response flag:" +
			 format(self.query_byte_3, '08b'), verb=3)

	def setRecursionOff(self):
		## Byte 4 of header contains RCode / error code and
		## recursion flag:
		#self.query_byte_4 = self.query_header[3:4]
		#self.query_byte_4 = self.query_byte_4 ^ 128
		## unpack subset of header to get 0th element of tuple, which
		## can be OR'd (^) with 128 to set recursion bit off:
		self.query_byte_4 = unpack('!B', self.query_header[3:4])[0] ^ 128
#		self.query_header = self.query_header[:3] \
#			+ pack('!B', self.query_byte_4) \
#			+ self.query_header[5:]
		debugMessage(msg="byte 4 w/ recursion flag:"
			 + format(self.query_byte_4, '08b'), verb=2)

	def addAnswer(self):
		self.answer_count += 1
		print "NEW answer_count: ", self.answer_count

	def subAnswer(self):
		self.answer_count = max(self.answer_count -1, 0)
		print "NEW answer_count: ", self.answer_count

	def addAdditional(self):
		self.addl_rec_count += 1
		print "NEW additional_count: ", self.answer_count

	def subAdditional(self):
		self.addl_rec_count = max(self.addl_rec_count - 1, 0)
		print "NEW additional_count: ", self.addl_rec_count

	def addAuth(self):
		self.auth_rec_count += 1
		print "NEW auth_rec_count: ", self.auth_rec_count

	def subAuth(self):
		self.auth_rec_count = max(self.auth_rec_count - 1, 0)
		print "NEW auth_rec_count: ", self.auth_rec_count



	def SERVFAIL(self):
		debugMessage(msg=format(
			"SERVFAIL() before toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)
		self.query_byte_4 = self.query_byte_4 | 2
		debugMessage(msg=format(
			"SERVFAIL() after  toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)

	def NXDOMAIN(self):
		debugMessage(msg=format(
			"NXDOMAIN() before toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)
		self.query_byte_4 = self.query_byte_4 | 3
		debugMessage(msg=format(
			"NXDOMAIN() after  toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)

	def REFUSED(self):
		print "CLASS: REFUSED before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
		self.query_byte_4 = self.query_byte_4 | 5
		print "CLASS: REFUSED after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')

	def NXRRSET(self):
		print "CLASS: NXRRSET before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
		self.query_byte_4 = self.query_byte_4 | 8
		print "CLASS: NXRRSET after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')

	def NOTAUTH(self):
		debugMessage(msg=format(
			"NOTAUTH(NOT FOUND) before toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)
		self.query_byte_4 = self.query_byte_4 | 9
		debugMessage(msg=format(
			"NXDOMAIN(NOT FOUND) after  toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)

	def NOTZONE(self):
		print "CLASS: NOTZONE before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
		self.query_byte_4 = self.query_byte_4 | 10
		print "CLASS: NOTZONE after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')



	'''	def printHeader(self):
		print( "HEADER: \"%x%x%x%x%x%x%x\"" % (self.query_id \
			, self.query_byte_3 \
			, self.query_byte_4 \
			, self.question_count \
			, self.answer_count \
			, self.auth_rec_count \
			, self.addl_rec_count \
			))'''

	def getHeader(self):
		xyz = pack( "!HBBHHHH", self.query_id \
			, self.query_byte_3 \
			, self.query_byte_4 \
			, self.question_count \
			, self.answer_count \
			, self.auth_rec_count \
			, self.addl_rec_count \
			)
		# print "Length header: ", len(xyz)

		return xyz



	def createResourceRecord( self, QNames, QType, QClass, QTTL, QAnswer):
	#		print "createResourceRecord! ==========================="
	#		print "Qnames:", QNames
		debugMessage(msg=format("QType: %r QClass: %r" \
			% (QType, QClass)), verb=3)
		debugMessage(msg=format( "QAnswer: %r" % QAnswer), verb=3)

		## ANY Query type is handled specially:
		## Instead return an "Additional" "TXT" record FIRST
		if unpack('!H', QType)[0] == 255:
			## QAnswer += '     Type ANY not supported   ' \
			##	+"'See draft-ietf-dnsop-refuse-any'"
			oneQuery.ResourceRec.append( \
				createResourceRecord( \
					QNames, pack('!H', 16), \
						QClass, \
					QTTL, \
					'Type ANY not supported   See draft-ietf-dnsop-refuse-any'
					)
				)
			QType = pack('!H', 1) ## i.e. 16 aka TXT

		returnString = ''

		for oneName in QNames:
			lenName = len(oneName)
			debugMessage(msg=format("One NAME: %s  and length: %d" \
				% (oneName, lenName)), verb=3)
			returnString += pack("!B", lenName)
			returnString += oneName
		## Finish off name with NULL byte:
		returnString += pack("!B", 0)
		## Followed by Type (MX), Class (IN), and TTL:
		returnString += QType + QClass
		returnString += pack("!i", QTTL)

		## MX records get a 2-byte Preference value first:
		if unpack('!H', QType)[0] == 15:
			## Answer is NOT 4 octets of IP address but domain name in
			## STD DNS NAME format, with length bytes preceding each
			## portion, and trailing NULL byte.
			## ALSO, preceding all that is 2-byte Preference value 
			## which must be included in field length indicator
			returnString += str(pack("!H", len('.'.join(QNames)) + 2 + 2 ) )
			print "QType == MX, adding fields to RR:", repr(QType)
			returnString += pack('!H', 1)  ## Arbitrary Preference value = 1
			for oneName in QNames:
				lenName = len(oneName)
				print "One NAME: %s  and length: %d" % (oneName, lenName)
				returnString += pack("!B", lenName)
				returnString += oneName
			returnString += pack("!B", 0)

		## TXT records:
		elif unpack('!H', QType)[0] == 16: #  or  unpack('!H', QType)[0] == 255:
			debugMessage(msg=format("QType == TXT," \
				+ " adding fields to RR: len: %d value: %s" \
					% (len(QAnswer), QAnswer ) ), verb=4)

			## Multiple strings allowed in answers:
			if (type(QAnswer) == list):
				returnString += str(pack("!H", len(' '.join(QAnswer) ) +1) )
				for oneAnswer in QAnswer:
					returnString += str(pack("!B", len(oneAnswer)))
					returnString += oneAnswer
			else:	## assume type(QAnswer) = string
					## (TODO test whether valid)
				returnString += str(pack("!H", len(QAnswer) +1) )
				returnString += str(pack("!B", len(QAnswer) ) )
				returnString += QAnswer
		else:
		## "A" type record, 2-byte length prefix:
			returnString += pack("!H", 4)
			for octet in QAnswer.split('.'):
	#			print "OCTET:", octet
				returnString += pack("!B", int(octet) )

		debugMessage(msg=format(
			"RESOURCE RECORD RETURN len: %d  and VALUE: %s" \
			% (len(returnString), repr(returnString))
			), verb=4)
		return returnString


	def setTTL(self, newTTL):
		print "CLASS: setTTL before:", self.QTTL,
		self.QTTL = newTTL
		print "CLASS: setTTL after:", self.QTTL










## #######################################################

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(( IP_ADDR, IP_PORT))
	debugMessage(format("Bound to IP :: port --> %s :: %s " \
		% (IP_ADDR, IP_PORT) ), \
		verb=0);
	print >> logFH, time.strftime('%Y-%m-%d %H:%M:%S'), \
		"STARTED LISTENING"
except:
	print "\nERROR binding to socket at %s :: %d:\n\t%s" \
		% (IP_ADDR, IP_PORT, exc_info()[1] )
	raise SystemExit







## #######################################################
threads = []

while(True):
	## data = conn.recv(BUFFER_SIZE)
	(data, (client_ip, client_port)) = s.recvfrom(BUFFER_SIZE)
	## client_ip, client_port = (client_ip_port)
	if not data: break
	# data = data.rstrip('\r\n')
	newthread = ClientThread(client_ip,client_port)
	newthread.start()
	threads.append(newthread)


	## ##############################################################
	## Header format (12 bytes)
	##
	## http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
	##
	## 2 bytes: QueryID: return to client for query q&a matching
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
	## ##############################################################






	## raise SystemExit  ## aka: sys.exit but without import sys



	for t in threads:
		t.join()





## RESOURCE RECORD RETURN len: 40  and VALUE: '\x0cdetectportal\x07firefox\x03com\x00\x00\x01\x00\x01\x00\x00\x04\xd2\x00\x04\x9d4\x0f\xcd'

## \x06austin\x04logs\x04roku\x03com\x00\x00\x01\x00\x01\x00\x00\x04\xd2\x00\x04\x9d4\x0f\xcd

## Traceback (most recent call last):
#  File "myoutsideip.py", line 314, in <module>
#    x = DNSquery(data)
#  File "myoutsideip.py", line 95, in __init__
 #   print "QType (A vs MX): %s " % self.qtypeCodes[ unpack('!H', self.QType)[0]],
## KeyError: 28
## KeyError: 33  <-- SRV type record requested
