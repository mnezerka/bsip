#!/usr/bin/python

import sys
import time
import copy
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener, DigestAuthenticator
from accountmanager import *

SERVER_IP = '127.0.0.1'
SERVER_PORT = 60001
CLIENT_IP = SERVER_IP
CLIENT_PORT = SERVER_PORT + 1

CLIENT_IP = "64.9.169.27"
CLEINT_PORT = 60001
SERVER_IP = "22.10.31.72"
SERVER_PORT = 5060
OUTBOUND_PROXY = SERVER_IP + ':' + str(SERVER_PORT)

user1 = User()
user1.setUserName('ITSY000001')
user1.setDisplayName('ITSY000001')
user1.setSipDomain('brn10.iit.ims')
user1.setAuthUserName('ITSY000001.priv@brn10.iit.ims')
user1.setAuthPassword('31000000001')

accounts = AccountManager()
accounts.add(user1, True)

localHop = Hop()
localHop.setHost(CLIENT_IP)
localHop.setPort(CLIENT_PORT)

STATE_REGISTRATION = 'reg'
STATE_DEREGISTRATION = 'dereg'
STATE_FINISHED = 'finished'

class SipClient(SipListener):

	def __init__(self):
		self.stack = SipStack({
			SipStack.PARAM_STACK_NAME: "registration",
			SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY,
			SipStack.PARAM_CREATE_TRANSACTIONS: True})
		self.msgFactory = MessageFactory()
		self.headerFactory = HeaderFactory()
		self.state = STATE_REGISTRATION

	def run(self):
		try:
			self.stack.start()
			udpListeningPoint = SipListeningPoint(self.stack, CLIENT_IP, CLIENT_PORT, Sip.TRANSPORT_UDP);
			self.stack.addListeningPoint(udpListeningPoint)
			self.stack.addSipListener(self)
			authenticator = DigestAuthenticator(self.stack, accounts)
			self.stack.addSipInterceptor(authenticator)

			self.registerRequest = MessageFactory.createRequestRegister(user1, localHop)
			tran = self.stack.createClientTransaction(self.registerRequest)
			print "sending REGISTER"
			tran.sendRequest()
			time.sleep(1)
		finally:
			self.stack.stop()

	def processResponse(self, responseEvent):
		response = responseEvent.getResponse()
		print "incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase())

		if self.state == STATE_REGISTRATION:

			if response.getStatusCode() == 200:
				print "registration finished"

				self.state = STATE_DEREGISTRATION

				#dereg = MessageFactory.createRequestRegister(user1, localHop)
				dereg = MessageFactory.createRequestDeRegister(self.registerRequest)

				tran = self.stack.createClientTransaction(dereg)
				print "sending deREGISTER"
				tran.sendRequest()

		elif self.state == STATE_DEREGISTRATION:
			print "incoming message in deregistration state"
		else:
			print "unknown state"

### main ##############################

sipClient = SipClient()
sipClient.run()

