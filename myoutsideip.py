#!/usr/bin/python

"""
BlackHoleDNS:

WAN-side IP address identification via:
	dig my.ip @[server]
This replicates the myoutsideip.net service that's gone offline.

Return domain not found (NXDOMAIN) for sites included in
the file NXDOMAIN.list (trackers, ad servers, etc.).

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
#
## Upgrading to python3:
## from SocketServer import ThreadingMixIn
from socketserver import ThreadingMixIn
#
## Potentially will use this to reload config if date changes:
import time
## Keep © notice current automatically with datetime:
import datetime as dt



## raise SystemExit




## http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
## https://docs.python.org/2/library/socketserver.html#socketserver-udpserver-example


IP_ADDR = '0.0.0.0'
## IP_ADDR = '127.0.0.1'		## for localhost testing
## Port can be changed with --port switch
IP_PORT = 53535			## for localhost testing
## IP_PORT = 53


BUFFER_SIZE = 512

## CONFDIR = '/etc/BlackHoleDNS'
CONFDIR = '.'
## Output verbosity level
## Can change with --debug:[0-4]
verbosityGlobal = 2
## For future feature - reloading config file when it changes
NXDOMAINfileTimestamp = 0
## Can change with --config switch
logFile = '/var/log/dns-blackhole.log'
## logFile = './dns-blackhole.log'












## #######################################################
##
## A logging utility for debugging messages. NOT for logging
## queries to a log file.
##
## This requires some disambiguation...
##
## Accepts 3 forms of parameters; mutually exclusive:
##
## debugMessage('A message', 4)
## or
## debugMessage(msg='A message', verb=4)
## or
## debugMessage("A message")
##
## The third format uses the global debug level (default 2, can be set
## via the --debug: argument at startup)
##
## The second format is handy when expanding functionality at
## later date.
##
## Note that methods cannot be mixed in same invocation
##
## Logging default level is 2 (4 is a lot, 0 is nearly nothing):
##
## See verbosityGlobal variable above for its initialization.
##
## #######################################################

##def debugMessage(message, *positional_parameters, **keyword_parameters):
def debugMessage(msgBare = None, verbBare = None, **keywords):
	"""
	All logging in central location, with customizable
	verbosity setting (via --debug=[0-4] as startup argument.
	"""

	## verbosityLocal is set by passed parameters;
	## can be different then global verbosityGlobal:
	verbosityLocal = None
	global verbosityGlobal

	## Check for msg="A message", verb=4 format of invocation:
	if ('msg' in keywords):
		msg = keywords['msg']
		## print( 'MESSAGE: ', msg )
	elif (msgBare == None):
		print( 'debugMessage() received NO MESSAGE...' )
		return
	else:
		msg = msgBare
	##
	if ('verb' in keywords):
		verbosityLocal = keywords['verb']
		## print( 'VERB: ', verbosityLocal )
	elif (verbBare == None):
		verbosityLocal = verbosityGlobal
	else:
		verbosityLocal = verbBare


	## This invocation may use a debug level (verb=N) different than the
	## global / default level.
	##
	## e.g. If a message is critical to display at any global debug level, use
	## debugMessage("Important Message!", 0)
	## But, if it's merely a debug notice, not normally displayed, use
	## debugMessage("blah blah blah", 4)
	if verbosityLocal <= verbosityGlobal:
		print( " * {}".format(msg ) )








## #######################################################
## Recognized arguments:
##	--debug:[0-4]
##		Sets the output verbosity levels: 0 (min) to 4 (max)
##	--config:
##		Sets the config file location directory
##	--log
##	--log-file:
##		Sets the log file
##	--port:
##		Sets the listening port
## #######################################################

def parseArgs(keywords):
	"""
	Handle command line arguments by setting appropriate values
	"""
	## print( "keywords: %r,  len keywords: %d" % (keywords, len(keywords)) )
	##
	## Parse keywords for recognized arguments:
	for oneWord in keywords:
		match = None

		##
		## Check for --debug
		match = re.match('(--debug)[=:](.+)', oneWord)
		if match and len(match.groups() ) == 2:
			global verbosityGlobal
			verbosityGlobal = int(match.group(2) )
			debugMessage( f"{match.group(1)} set to {str(verbosityGlobal)}", 1 )
			continue

		##
		## Check for --conf --config --conf-dir --config-dir
		match = re.search('(--conf(?:ig)?(?:-dir)*)[=:](.+)', oneWord)
		if match and len(match.groups() ) >= 2:
			global CONFDIR
			CONFDIR = match.group(2)
			debugMessage( f"{match.group(1)} set to {CONFDIR}", 1 );
			continue

		##
		## Check for --log --log-file --logfile
		match = re.search('(--log(?:-?file)?)[=:](.+)', oneWord)
		if match and len(match.groups() ) >= 2:
			global logFile
			logFile = match.group(2)
			debugMessage( f"{match.group(1)} set to {logFile}", 1 )
			continue

		##
		## Check for --port
		match = re.search('(--port)[=:](.+)', oneWord)
		if match and len(match.groups() ) >= 2:
			global IP_PORT
			IP_PORT = int(match.group(2))
			debugMessage( f"{match.group(1)} set to {str(IP_PORT)}", 1 )
			continue

		##
		## Catch unknown args:
		if match == None:
			debugMessage( f"\nWARNING: Unrecognized argument: {str(oneWord)}", 0 )
			raise SystemExit







## #######################################################
## Parse command line arguments if supplied (argv[0] is script name):
##
if (len(argv) > 1):
	args = argv[1:]
	## print( "ARGS: %r,  len ARGS: %d" % (args, len(args)) )
	##
	## Skip script name (argv[0]) when parsing:
	parseArgs( argv[1:] )




## Compose location of the list of NXDOMAINs from user-overridable options,
## stripping extra directory separators while doing so:
NXDOMAINfile = re.sub('//', '/', CONFDIR + '/NXDOMAIN.list' )






## #######################################################
##
def loadNXDOMAINfile():
	"""
	Load the file of domains to "black-hole", i.e. give not-found
	message for (aka NXDOMAIN)
	"""
	global NXDOMAINs
	global NXDOMAINfile

	## Get the timestamp of that file, maybe in future check it for changes and
	## auto-reload it:
	try:
		global NXDOMAINfileTimestamp
		NXDOMAINfileTimestamp = stat(NXDOMAINfile).st_mtime
		NXDOMAINs = open(NXDOMAINfile, 'r').read().splitlines()
	except:
		debugMessage( f"ERROR: {exc_info()[1]}", 0 )
		raise SystemExit


	## Remove comments:
	##
	index = 0
	kounter = 0
	##
	while index < len(NXDOMAINs):
		NXDOMAINs[index] = re.sub('[\t ]*#+.*$','', NXDOMAINs[index] ).lower()
		if len(NXDOMAINs[index]) == 0:
			kounter += 1
			del NXDOMAINs[index]
		else:
			index += 1

	if kounter > 0:
		debugMessage( f"DELETED {kounter} comments from {NXDOMAINfile}", 4)



loadNXDOMAINfile()






## #######################################################
## Open log file
##
try:
	## logFH = open(logFile, 'ab')	## append, binary (unlikely useful)
	logFH = open(logFile, 'a')	## append
	## print( "Opened log file %s" % logFile )
	debugMessage( f"Opened log file {logFile}", 2 )
except:
	debugMessage( f"ERROR: {exc_info()[1]}", 0 )
	raise SystemExit













## #######################################################
## Give each query its own thread
##
class ClientThread(Thread):

	def __init__(self, ip, port):
		Thread.__init__(self)
		self.ip = ip
		self.port = port
		debugMessage(msg="---------------------------\n"
			+ f"[+] New thread started for {ip}:{str(port)}",
			verb=2)

	def run(self):
		debugMessage(f"Connection: client IP:{client_ip} "
			+ f"sent {len(data)} bytes", 2)

		debugMessage(msg=f"Received query data: {repr(data)}", verb=4 )


		## Build a query object, set response flag, etc:
		oneQuery = DNSquery(data)
		oneQuery.setResponseFlag()
		oneQuery.setRecursionOff()


		query_domain = oneQuery.getQuestionNameCanonical().lower()
		debugMessage( msg=f"Question is for: {query_domain.decode()}",
			verb=1)

		## Check for a black-holed domain name:
		nxdomainFound = False
		##
		for domain in NXDOMAINs:
			if query_domain.decode().endswith( domain ):
				debugMessage( msg=f'NXDOMAIN match: {domain}', verb=2)
				oneQuery.NXDOMAIN()
				oneQuery.subAnswer()
				nxdomainFound = True
				break


		"""
		Black holes get NXDOMAIN,
		"my.ip" gets real reply,
		possibly-valid but unknown domains get SERVFAIL, i.e. "don't know"
		"""
		debugMessage( f"nxdomainFound: {nxdomainFound}", 4)

		if not nxdomainFound:
			if query_domain[0:5].decode() == 'my.ip':
				debugMessage( "Found my.ip query", 4)
				## True when looking for WAN-side IP via:
				## dig my.ip @[this-server]
				## Replicates dig my.ip @outsideip.net
				oneQuery.ResourceRec.append(
					oneQuery.createResourceRecord(oneQuery.QNames,
					oneQuery.QType, oneQuery.QClass, 0, client_ip))
				oneQuery.addAnswer()

				## Add a boastful TXT RR, because why not?
				oneQuery.ResourceRec.append(
					oneQuery.createResourceRecord(oneQuery.QNames,
						pack('!H', 16),
						oneQuery.QClass,
						86400,
						['(c)', 'Ronald Barnes', f'2017-{dt.datetime.now().year}']
						)
					)
				oneQuery.addAdditional()
			else:
				## Standard reply for non-recursive "Not Found"
				## Test this via: dig cbc.ca @8.8.8.8 +norecurse
				oneQuery.SERVFAIL()


		debugMessage( f"oneQuery.ResourceRec: {oneQuery.ResourceRec}", 4)


		retval = oneQuery.getHeader()
		retval += oneQuery.questionName
		for item in oneQuery.ResourceRec:
			retval += item


		## Send reply back to remote client:
		s.sendto(retval, (client_ip, client_port))


		## This goes to log file:
		print( time.strftime('%Y-%m-%d %H:%M:%S', time.localtime() ),
			query_domain, nxdomainFound, file=logFH
			)
		logFH.flush()
		debugMessage( f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime() )} "
			+ f"query_domain:{query_domain.decode()} "
			+ f"NXDOMAIN:{nxdomainFound}", 4
			)






## #######################################################

class DNSquery:
	"""
	Turn DNS query into object, manipulate flag fields/bits,
	set status flags/bits, compose appropriate ResourceRecord
	for reply.
	"""
	## Type "A" is only one relevant to "dig my.ip", others may be
	## implemented if need arises.  This is a subset of possiblities.
	qtypeCodes = {
		  1: "A",
		  2: "NS",
		  5: "CNAME",
		  6: "SOA",
		 10: 'NULL',
		 11: 'WKS',
		 12: "PTR",
		 13: "HINFO",
		 15: "MX",
		 16: "TXT",
		 33: 'SRV',
		252: 'AFXR',
		255: 'ANY'
		}

	## Types of queries (a subset): only 0: Standard Query is implemented:
	opCodes = {
		0: "Std Query",
		2: "Status",
		4: "Notify",
		5: "Update"
		}



	def __init__(self, query):
		## An array of Resource Records that may be returned to client:
		self.ResourceRec = []
		del self.ResourceRec[0:]

		## Header gets rebuilt with some bits fiddled:
		## Retrieve it with getHeader()
		self.query_header = query[:12]
		self.query_id, = unpack('!H', self.query_header[:2] )
		debugMessage( f"QueryID: {str(self.query_id)}", 2)

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
		debugMessage( f"question_count: {str(self.question_count)}", 3)

		## Answer count will be 1 in most / all cases
		self.answer_count = self.query_header[6:8]
		self.answer_count, = unpack('!H', self.answer_count)
		debugMessage( f"answer_count: {str(self.answer_count)}", 4)

		## Unlikely to add auth records, ought to always be zero
		self.auth_rec_count = self.query_header[8:10]
		self.auth_rec_count, = unpack('!H', self.auth_rec_count)
		debugMessage( f"auth_rec_count: {str(self.auth_rec_count)}", 4)

		## May have additional records for TXT or ANY type queries,
		## or for adding fancy (c) notices
		self.addl_rec_count = self.query_header[10:12]
		self.addl_rec_count, = unpack('!H', self.addl_rec_count)
		debugMessage( "Received query's addl_rec_count: "
			+ f"{str(self.addl_rec_count)}", 2)
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

			offsetNamePart = lenNamePart
			lenNamePart += 1


		debugMessage(msg= "QNames (Queried Name): "
			+ '.'.join( element.decode() for element in self.QNames), verb=3)


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

		debugMessage( f"QClass (IN=1): {unpack('!H', self.QClass)[0]}", 4)


		self.questionName = self.questionName[:lenNamePart]

		debugMessage( "questionName from query data is "
			+ f"{len(self.questionName)} bytes: \n\t"
			+ f"{repr(self.questionName)}",
			3)
		## end __init__




	def getQuestionNameCanonical(self):
		"""
		Return human-readable "question name" (domain) for logging, etc.
		The binary lengths stripped, separators of "." added.
		"""
		debugMessage( f"self.QNames: {self.QNames}", 4 )
		return b".".join(self.QNames)



#	def getQNames(self):
#		debugMessage(msg=format("getQNames() returning: %r" % self.QNames),
#			 verb=4)
#		return self.QNames




	def setResponseFlag(self):
		self.query_byte_3 = self.query_header[2:3]
		self.query_byte_3, = unpack('!B', self.query_header[2:3])
		## set response flag ON
		# self.response = self.query_byte_3 ^ 128
		## print "Response flag set: from: ", format(self.query_byte_3, '08b'),
		self.query_byte_3 = self.query_byte_3 ^ 128
		## self.query_header = self.query_header[:2] \
		##	+ pack('!B', self.query_byte_3) \
		##	+ self.query_header[4:]
		##
		## ERROR on substring assignment:
		## self.query_header[2:3] = pack('!16', unpack('!B', self.query_header[2:3])[0] ^ 128)
		## print( " to: ", format(self.query_byte_3, '08b') )
		debugMessage( msg="byte 3 w/ query/response flag:"
			+ format(self.query_byte_3, '08b'),
			verb=3)



	def setRecursionOff(self):
		## Byte 4 of header contains RCode / error code and recursion flag:
		## self.query_byte_4 = self.query_header[3:4]
		## self.query_byte_4 = self.query_byte_4 ^ 128
		## unpack subset of header to get 0th element of tuple, which
		## can be OR'd (^) with 128 to set recursion bit off:
		self.query_byte_4 = unpack('!B', self.query_header[3:4])[0] ^ 128
		## self.query_header = self.query_header[:3] \
		##	+ pack('!B', self.query_byte_4) \
		##	+ self.query_header[5:]
		debugMessage(msg="byte 4 w/ recursion flag:"
			+ format(self.query_byte_4, '08b'),
			verb=2)



	def addAnswer(self):
		## Increment Answer field count:
		self.answer_count += 1
		debugMessage( f"Incremented answer_count to: {self.answer_count}", 3)

	def subAnswer(self):
		## Decrement Answer field count:
		self.answer_count = max(self.answer_count -1, 0)
		debugMessage( f"Decremented answer_count to: {self.answer_count}", 3)




	def addAdditional(self):
		## Increment Additional info field counter:
		self.addl_rec_count += 1
		debugMessage( f"Incremented additional_count: {self.addl_rec_count}", 3)

	def subAdditional(self):
		## Decrement Additional info field counter:
		self.addl_rec_count = max(self.addl_rec_count - 1, 0)
		debugMessage( f"Decremented additional_count: {self.addl_rec_count}", 3)



	def addAuth(self):
		## Increment Authority info field counter:
		self.auth_rec_count += 1
		debugMessage( f"Incremented auth_count: {self.auth_rec_count}", 3)

	def subAuth(self):
		## Decrement Authority info field counter:
		self.auth_rec_count = max(self.auth_rec_count - 1, 0)
		debugMessage( f"Decremented auth_count: {self.auth_rec_count}", 3)



	def SERVFAIL(self):
		## SERVFAIL means "unknown" and clients should try a secondary server:
		debugMessage(msg=format(
			"SERVFAIL() byte 4 before toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)
		self.query_byte_4 = self.query_byte_4 | 2
		debugMessage(msg=format(
			"SERVFAIL() byte 4 after  toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)


	def NXDOMAIN(self):
		## NXDOMAIN means "known not to exist" and clients should not
		## try a secondary server
		## This is used for malware / ad servers
		debugMessage(msg=format(
			"NXDOMAIN() byte 4 before toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)
		self.query_byte_4 = self.query_byte_4 | 3
		debugMessage(msg=format(
			"NXDOMAIN() byte 4 after  toggle: %d  binary: %s"
			% (self.query_byte_4, format(self.query_byte_4, '08b'))),
			verb=3)


	def REFUSED(self):
		print( "CLASS: REFUSED before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)
		self.query_byte_4 = self.query_byte_4 | 5
		print( "CLASS: REFUSED after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)

	def NXRRSET(self):
		print( "CLASS: NXRRSET before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)
		self.query_byte_4 = self.query_byte_4 | 8
		print( "CLASS: NXRRSET after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)

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
		print( "CLASS: NOTZONE before:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)
		self.query_byte_4 = self.query_byte_4 | 10
		print( "CLASS: NOTZONE after:", self.query_byte_4, \
			" binary: ", format(self.query_byte_4, '08b')
			)



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
		header = pack( "!HBBHHHH",
			self.query_id,
			self.query_byte_3,
			self.query_byte_4,
			self.question_count,
			self.answer_count,
			self.auth_rec_count,
			self.addl_rec_count,
			)
		debugMessage( f"getHeader() length: {len(header)} header: {header}", 4 )
		return header



	def createResourceRecord( self, QNames, QType, QClass, QTTL, QAnswer):
		## Resource Record is an answer record
		debugMessage( "createResourceRecord() \n"
			+ f"	QType: {QType}\n"
			+ f"	QClass: {QClass}\n"
			+ f"	QTTL: {QTTL}\n"
			+ f"	QAnswer: {QAnswer}",
			3)
#		debugMessage( f"QAnswer: {QAnswer}", 3)

		## Query type ANY is handled specially:
		## Instead return an "Additional" "TXT" record FIRST
		## NOTE: NOW CONNECTION REFUSED WHEN -t any IS USED?!?
		## NOTE: NOW CONNECTION REFUSED WHEN -t any IS USED?!?
		## NOTE: NOW CONNECTION REFUSED WHEN -t any IS USED?!?
		## NOTHING IN LOG
		if unpack('!H', QType)[0] == 255:
			## QAnswer += '     Type ANY not supported   ' \
			##	+"'See draft-ietf-dnsop-refuse-any'"
			oneQuery.ResourceRec.append(
				createResourceRecord(
					QNames, pack('!H', 16),
					QClass,
					QTTL,
					'Type ANY not supported   See draft-ietf-dnsop-refuse-any'
					)
				)
			QType = pack('!H', 1) ## i.e. 16 aka TXT

		returnString = b''

		for oneName in QNames:
			lenName = len(oneName)
#			debugMessage(msg=format("One NAME: %s  and length: %d" \
#				% (oneName, lenName)), verb=3)
			debugMessage( f"QNames' oneName: {oneName} and length: {len(oneName)}",
				3)
			returnString += pack("!B", len(oneName))
			returnString += oneName

		## Finish off name with NULL byte:
		returnString += pack("!B", 0)
		## Followed by Type (MX), Class (IN), and TTL:
		returnString += QType + QClass
		returnString += pack("!i", QTTL)

		## MX records
		## MX records
		## MX records
		## MX records get a 2-byte Preference value first:
		if unpack('!H', QType)[0] == 15:
			## Answer is NOT 4 octets of IP address but domain name in
			## STD DNS NAME format, with length bytes preceding each
			## portion, and trailing NULL byte.
			## ALSO, preceding all that is 2-byte Preference value
			## which must be included in field length indicator

			## Join together all parts of question's "names" i.e. "my" and "ip":
			tempVal = ".".join(item.decode() for item in QNames)
			## Adding 2 + 2 suffix: is that because len(my) = 2 and len(ip) = 2?
			## Probably - if an NXDOMAIN record, this branch never executes.
			## And, this script is not a real DNS lookup tool, so "my.ip" is the
			## only way to get here.
			## HOWEVER, let's make it extensible
			## returnString += pack("!H", len(tempVal) + 2 + 2)
			returnString += pack("!H", len(tempVal)
				+ len("".join( item.decode() for item in QNames) )
				)

			debugMessage( f"QType == MX, adding fields to RR: {repr(QType)}", 3 )

			returnString += pack('!H', 1)  ## Arbitrary Preference value = 1
			for oneName in QNames:
				debugMessage( f"MX QNames' oneName: {oneName} length: {len(oneName)}",
					4)
				## Return value gets (binary) length of following value:
				returnString += pack("!B", len(oneName))
				returnString += oneName

			## Finish return value with NULL:
			returnString += pack("!B", 0)


		## TXT records:
		## TXT records:
		## TXT records:
		elif unpack('!H', QType)[0] == 16:
			debugMessage( f"QType == TXT, adding fields to RR: "
				+ f"{QAnswer}  length: {len(QAnswer)}", 3 )

			## Multiple strings allowed in answers:
			if (type(QAnswer) == list):
##				returnString += str(pack("!H", len(' '.join(QAnswer) ) +1) )
				returnString += pack("!H", len(' '.join(QAnswer) ) +1)
				for oneAnswer in QAnswer:
					returnString += pack("!B", len(oneAnswer))
					print( f"type(oneAnswer) == {type(oneAnswer)} & oneAnswer:{oneAnswer}" )
					returnString += bytes(oneAnswer, "utf-8")
			else:	## assume type(QAnswer) = string
					## (TODO test whether valid)
				returnString += pack("!H", len(QAnswer) +1)
				returnString += pack("!B", len(QAnswer) )
				returnString += bytes(QAnswer, "utf-8")
		else:
		## "A" type record, 2-byte length prefix:
			returnString += pack("!H", 4)
			for octet in QAnswer.split('.'):
				print( f"OCTET: {octet}" )
				returnString += pack("!B", int(octet) )

		debugMessage(msg=format(
			"RESOURCE RECORD RETURN len: %d  and VALUE: %s" \
			% (len(returnString), repr(returnString))
			), verb=4)
		return returnString


	def setTTL(self, newTTL):
		print( "CLASS: setTTL before:", self.QTTL,)
		self.QTTL = newTTL
		print( "CLASS: setTTL after:", self.QTTL )










## #######################################################
## Bind to socket
## #######################################################
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(( IP_ADDR, IP_PORT))
	debugMessage(format("Bound to IP :: port --> %s :: %s " \
		% (IP_ADDR, IP_PORT) ), \
		verb=0);

except:
	print( "\nERROR binding to socket at %s :: %d:\n\t%s" \
		% (IP_ADDR, IP_PORT, exc_info()[1] )
		)
	raise SystemExit


## #######################################################
## Log start time to log file
## #######################################################
try:
	## print >> logFH, time.strftime('%Y-%m-%d %H:%M:%S'), \
	##		"STARTED LISTENING"
	print( time.strftime('%Y-%m-%d %H:%M:%S'), "STARTED LISTENING",
		file=logFH
		)

except:
	print( "\nERROR writing to log file: ", logFH)
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
