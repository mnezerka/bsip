#!/usr/bin/python

from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener
import sys
import time
from accountmanager import *

SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

bob = User()
bob.setUserName('bob')
bob.setDisplayName('Bob')
bob.setSipDomain('biloxi.com')
bob.setAuthUserName('bobuser')
bob.setAuthPassword('bobpasswd')

alice = User()
alice.setUserName('alice')
alice.setDisplayName('Alice')
alice.setSipDomain('atlanta.com')
alice.setAuthUserName('aliceuser')
alice.setAuthPassword('alicepasswd')

def createSipAddressForUser(user):
	result = SipAddress()
	result.setDisplayName(user.getDisplayName())
	uri = SipUri()
	uri.setScheme(Uri.SCHEME_SIP)
	uri.setUser(user.getUserName())
	uri.setHost(user.getSipDomain())
	result.setUri(uri)
	return result

class SipClient(SipListener):

	def __init__(self):
		
		self.s = SipStack({ SipStack.PARAM_STACK_NAME: "bsip", SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY, SipStack.PARAM_CREATE_TRANSACTIONS: True })
		self.msgFactory = MessageFactory()

	def run(self):

		bobSipAddr = createSipAddressForUser(bob)
		aliceSipAddr = createSipAddressForUser(alice)

		m = SipRequest()
		m.setMethod(SipRequest.METHOD_INVITE)
		requestUri = aliceSipAddr.getUri()
		m.setRequestUri(requestUri)
		fromHeader = SipFromHeader()
		fromHeader.setAddress(bobSipAddr)
		fromHeader.setTag(SipUtils.generateTag())
		m.addHeader(fromHeader)
		toHeader = SipToHeader()
		toHeader.setAddress(aliceSipAddr)
		m.addHeader(toHeader)

		m.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier(CLIENT_IP)))

		m.addHeader(SipCSeqHeader('1 %s' % m.getMethod()))
		m.addHeader(SipViaHeader('SIP/2.0/UDP some.host;lskpmc=P01'))

		contactUri = SipUri()
		contactUri.setScheme(Uri.SCHEME_SIP)
		contactUri.setHost(CLIENT_IP);
		contactUri.setPort(CLIENT_PORT);
		contactHeader = ContactHeader()
		contactHeader.setAddress(contactUri)
		m.addHeader(contactHeader);

		#m.setContent("This is the body of the messsage")

		try:
			self.s.start()
			udpListeningPoint = SipListeningPoint(self.s, SERVER_IP, SERVER_PORT, Sip.TRANSPORT_UDP);
			self.s.addListeningPoint(udpListeningPoint)
			self.s.addSipListener(self)

			tran = self.s.createClientTransaction(m)
			tran.sendRequest()
			print "Waiting 1s to process all pending messages"
			time.sleep(1)
		finally:
			self.s.stop()
		

	def processRequest(self, requestEvent):
		print "Incoming request, method is %s" % requestEvent.getRequest().getMethod()
		response = self.msgFactory.createResponse(200, requestEvent.getRequest())
		serverTrans = requestEvent.getServerTransaction()
		print "Sending 200 OK response"
		serverTrans.sendResponse(response)

	def processResponse(self, responseEvent):
		response = responseEvent.getResponse()
		clientTrans = responseEvent.getClientTransaction()
		print "Incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase())

### main ##############################

sipClient = SipClient()
sipClient.run()


