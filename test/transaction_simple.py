#!/usr/bin/python

from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener
import sys
import time

SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

class SipClient(SipListener):

	def __init__(self):
		
		self.s = SipStack({ SipStack.PARAM_STACK_NAME: "bsip", SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY, SipStack.PARAM_CREATE_TRANSACTIONS: True })
		self.msgFactory = MessageFactory()

	def run(self):
		m = SipRequest()
		m.setMethod(SipRequest.METHOD_MESSAGE)
		requestUri = SipUri()
		requestUri.setScheme(Sip.URI_PREFIX_SIP)
		requestUri.setUser('alice')
		requestUri.setHost('blue.com')
		m.setRequestUri(requestUri)
		m.addHeader(SipFromHeader('sip:alice@blue.com'))
		m.addHeader(SipToHeader('sip:bob@blue.com'))
		m.addHeader(SipCallIdHeader('callid'))
		m.addHeader(SipCSeqHeader('34 %s' % SipRequest.METHOD_MESSAGE))
		m.addHeader(SipViaHeader('SIP/2.0/UDP some.host;lskpmc=P01'))
		#m.setContent("This is the body of the messsage")
		extensionHeader = Header('My-Header', 'my header value');
		m.addHeader(extensionHeader);

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


