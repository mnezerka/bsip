#!/usr/bin/python

import sys
import time
from sipmessage import *
from sipstack import User, SipStack, SipListeningPoint, SipListener, Authenticator


SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

user1 = User()
user1.setUserName('ITSY000001')
user1.setDisplayName('ITSY000001')
user1.setSipDomain('brn38.iit.ims')
user1.setAuthUserName('ITSY000001.priv@brn38.iit.ims')
user1.setAuthPassword('33800000001')

class SipClient(SipListener):

	def __init__(self):
		
		self.s = SipStack({ SipStack.PARAM_STACK_NAME: "ahoj", SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY})
		self.msgFactory = MessageFactory()
		self.headerFactory = HeaderFactory()

	def run(self):
		self.r = SipRequest()
		self.r.setMethod(Sip.METHOD_MESSAGE)
		requestUri = SipUri()
		requestUri.setScheme(Sip.URI_PREFIX_SIP)
		requestUri.setUser('alice')
		requestUri.setHost('blue.com')
		self.r.setRequestUri(requestUri)
		self.r.addHeader(SipFromHeader('sip:alice@blue.com'))
		self.r.addHeader(SipToHeader('sip:bob@blue.com'))
		self.r.addHeader(SipCallIdHeader('callid'))
		self.r.addHeader(SipCSeqHeader('34 REGISTER'))
		self.r.addHeader(SipViaHeader('SIP/2.0/UDP some.host;branch=z9hG4bKsomebranch;lskpmc=P01'))
		#m.setContent("This is the body of the messsage")
		extensionHeader = Header('My-Header', 'my header value');
		self.r.addHeader(extensionHeader);

		try:
			self.s.start()
			udpListeningPoint = SipListeningPoint(self.s, SERVER_IP, SERVER_PORT, Sip.TRANSPORT_UDP);
			#tcpListeningPoint = SipListeningPoint(self.s, SERVER_IP, SERVER_PORT, Sip.TRANSPORT_TCP);
			self.s.addListeningPoint(udpListeningPoint)
			#self.s.addListeningPoint(tcpListeningPoint)
			self.s.addSipListener(self)

			# send several messages
			for i in xrange(1):
				print "Sending message no: %d" % i
				self.s.sendRequest(self.r)
			print "Waiting 1s to process all pending messages"
			time.sleep(1)
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

			#accountManager = AccountManager()

			authenticator = Authenticator(self.headerFactory)

			authorization = authenticator.getAuthorization(
				self.r.getMethod(),
				str(self.r.getRequestUri()),
				content,
				authHeader,
				user1)

			#print 'Created authorization header: %s' % str(authorization)
			
			self.r.addHeader(authorization)

			self.s.sendRequest(self.r)

		#print str(responseEvent.getResponse())

### main ##############################

sipClient = SipClient()
sipClient.run()


