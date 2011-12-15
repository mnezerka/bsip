import sys
import time
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener


SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

class User1:
	userName = 'ITSY000001';
	domain= 'brn38.iit.ims';
	displayName = 'ITSY000001';
	authUserName = 'ITSY000001.priv@brn38.iit.ims';
	authPassword = '33800000001';

class SipClient(SipListener):

	def __init__(self):
		
		self.s = SipStack({ SipStack.PARAM_STACK_NAME: "ahoj", SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY})
		self.msgFactory = MessageFactory()

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
			authHeader.setRealm(User1.domain)
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

			TODO: Authorization.getAuthorization('Digest', User1.uri, requestBody, authHeader, userCredentials)

			# create authorization header
#			authorizationHeader = AuthorizationHeader()
#			authorizationHeader.setScheme('Digest')
#			authorizationHeader.setUserName(User1.authUserName)
#			authorizationHeader.setRealm(User1.domain)
#			authorizationHeader.setUri(User1.userName + "@" + User1.domain)
#			authorizationHeader.setNonce('')
#			authorizationHeader.setResponse('')
#			self.r.addHeader(authorizationHeader)
			self.s.sendRequest(self.r)

		#print str(responseEvent.getResponse())

### main ##############################

sipClient = SipClient()
sipClient.run()


