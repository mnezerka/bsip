#!/usr/bin/python

import sys
import time
import copy
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener, Authenticator
from accountmanager import *

SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1

CLIENT_IP = "64.17.181.198"
CLEINT_PORT = 60001
SERVER_IP = "22.66.32.72"
SERVER_PORT = 5060
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

user1 = User()
user1.setUserName('ITSY000001')
user1.setDisplayName('ITSY000001')
user1.setSipDomain('brn66.iit.ims')
user1.setAuthUserName('ITSY000001.priv@brn66.iit.ims')
user1.setAuthPassword('36600000001')

class SipClient(SipListener):

	def __init__(self):
		
		self.s = SipStack({ SipStack.PARAM_STACK_NAME: "ahoj", SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY})
		self.msgFactory = MessageFactory()
		self.headerFactory = HeaderFactory()

	def run(self):
		requestUri = SipUri('sip:%s' % user1.getSipDomain())
		user1Uri = SipUri('sip:%s@%s' % (user1.getUserName(), user1.getSipDomain()))
		user1SipAddress = SipAddress()
		user1SipAddress.setUri(user1Uri)
		user1SipAddress.setDisplayName(user1.getDisplayName())

		self.r = SipRequest()
		self.r.setMethod(Sip.METHOD_REGISTER)
		self.r.setRequestUri(requestUri)

		fromHeader = SipFromHeader()
		fromHeader.setAddress(user1SipAddress)
		fromHeader.setTag(SipUtils.generateTag())
		self.r.addHeader(fromHeader)
		toHeader = SipToHeader()
		toHeader.setAddress(user1SipAddress)
		self.r.addHeader(toHeader)

		self.r.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier(CLIENT_IP)))

		self.r.addHeader(SipCSeqHeader('1 REGISTER'))
		viaHeader = SipViaHeader('SIP/2.0/UDP some.host')
		viaHeader.setBranch(SipUtils.generateBranchId());
		self.r.addHeader(viaHeader)
		self.r.addHeader(MaxForwardsHeader('70'))
		self.r.addHeader(ExpiresHeader('3600'))

		contactUri = SipUri()
		contactUri.setScheme(Uri.SCHEME_SIP)
		contactUri.setHost(CLIENT_IP);
		contactUri.setPort(CLIENT_PORT);
		contactHeader = SipContactHeader()
		contactHeader.setAddress(contactUri)
		self.r.addHeader(contactHeader);

		# create authorization header
		authorizationHeader = AuthorizationHeader()
		authorizationHeader.setScheme('Digest')
		authorizationHeader.setUserName(user1.getAuthUserName())
		authorizationHeader.setRealm(user1.getSipDomain())
		authorizationHeader.setUri(str(requestUri))
		authorizationHeader.setNonce('')
		authorizationHeader.setResponse('')
		self.r.addHeader(authorizationHeader)

		try:
			self.s.start()
			udpListeningPoint = SipListeningPoint(self.s, CLIENT_IP, CLIENT_PORT, Sip.TRANSPORT_UDP);
			#tcpListeningPoint = SipListeningPoint(self.s, SERVER_IP, SERVER_PORT, Sip.TRANSPORT_TCP);
			self.s.addListeningPoint(udpListeningPoint)
			#self.s.addListeningPoint(tcpListeningPoint)
			self.s.addSipListener(self)

			# send several messages
			for i in xrange(1):
				print "Sending message no: %d" % i
				self.s.sendRequest(self.r)
			time.sleep(3)
		finally:
			self.s.stop()
		

	def processRequest(self, requestEvent):
		request = requestEvent.getRequest()
		print "Incoming request, method is %s" % request.getMethod()
		# check if authorization header is present
		authHeader = request.getHeaderByType(AuthenticationHeader)
		print "Auth header is: " + str(authHeader)
		response = None
		if authHeader is None:
			print "Sending 401 Not Authorized response"
			# create authorization header
			authHeader = WwwAuthenticateHeader()
			authHeader.setScheme('Digest')
			authHeader.setRealm(user1.getSipDomain())
			authHeader.setQop('int,auth-int')
			authHeader.setNonce('somenonce')
			authHeader.setOpaque('someopaque')
			#authHeader.setUserName(User1.authUserName)
			response = self.msgFactory.createResponse(401, requestEvent.getRequest())
			response.addHeader(authHeader)

		else:
			# check if authorization is valid
			print "Checking authorization"
			response = self.msgFactory.createResponse(200, requestEvent.getRequest())

		print "Sending response"
		self.s.sendResponse(response)

	def processResponse(self, responseEvent):
		response = responseEvent.getResponse()
		print "Incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase())
		if response.getStatusCode() == 401:

			authHeader = response.getHeaderByType(WwwAuthenticateHeader)

			if authHeader is None:
				raise ESipException('Could not find WWWAuthenticate or ProxyAuthenticate header');

			# Remove all authorization headers from the request (we'll re-add them from cache)
			self.r.removeHeadersByType(AuthorizationHeader)

			# Increment cseq
			cSeq = self.r.getHeaderByType(SipCSeqHeader)
                	cSeq.setSeqNumber(cSeq.getSeqNumber() + 1l)

			# set new tag and branch
			fromHeader = self.r.getHeaderByType(SipFromHeader)
			fromHeader.setTag(SipUtils.generateTag())
			topVia = self.r.getTopmostViaHeader()
			topVia.setBranch(SipUtils.generateBranchId())

			realm = authHeader.getRealm()
			authorization = None;

			# we haven't yet authenticated this realm since we were started.
			content = self.r.getContent()
			if content is None:
				content = ''

			authenticator = Authenticator(self.headerFactory)

			authorization = authenticator.getAuthorization(
				self.r.getMethod(),
				str(self.r.getRequestUri()),
				content,
				authHeader,
				user1)

			self.r.addHeader(authorization)

			self.s.sendRequest(self.r)

		elif response.getStatusCode() == 200:

			print "finished"

			# Increment cseq
			#cSeq = self.r.getHeaderByType(SipCSeqHeader)
                	#cSeq.setSeqNumber(cSeq.getSeqNumber() + 1l)

			#expiresHeader = self.r.getHeaderByType(ExpiresHeader)
			#expiresHeader.setExpires(0)			
			#self.s.sendRequest(self.r)


### main ##############################

sipClient = SipClient()
sipClient.run()


