#!/usr/bin/python

import sys
import time
import copy
import os
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
user1Addr = SipAddress()
user1Uri = SipUri()
user1Uri.setScheme(Uri.SCHEME_SIP)
user1Uri.setUser(user1.getUserName())
user1Uri.setHost(user1.getSipDomain())
user1Addr.setDisplayName(user1.getDisplayName())
user1Addr.setUri(user1Uri)

user2 = User()
user2.setUserName('ITSY000002')
user2.setDisplayName('ITSY000002')
user2.setSipDomain('brn10.iit.ims')
user2.setAuthUserName('ITSY000002.priv@brn10.iit.ims')
user2.setAuthPassword('31000000002')
user2Addr = SipAddress()
user2Uri = SipUri()
user2Uri.setScheme(Uri.SCHEME_SIP)
user2Uri.setUser(user2.getUserName())
user2Uri.setHost(user2.getSipDomain())
user2Addr.setDisplayName(user2.getDisplayName())
user2Addr.setUri(user2Uri)

accounts = AccountManager()
accounts.add(user1, True)
accounts.add(user2, True)

localHop = Hop()
localHop.setHost(CLIENT_IP)
localHop.setPort(CLIENT_PORT)

STATE_REGISTRATION = 'reg'
STATE_INVITE = 'invite'
STATE_DEREGISTRATION = 'dereg'
STATE_FINISHED = 'finished'

class SipClient(SipListener):

	def __init__(self):
		self.stack = SipStack({
			SipStack.PARAM_STACK_NAME: os.path.abspath(__file__),
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
		print "incoming response - state:%s %d %s" % (self.state, response.getStatusCode(),  response.getReasonPhrase())

		if self.state == STATE_REGISTRATION:

			if response.getStatusCode() == 200:
				print "registration finished"

				self.state = STATE_INVITE

				#dereg = MessageFactory.createRequestRegister(user1, localHop)
				invite = MessageFactory.createRequestInvite(user1Addr, user2Addr, localHop)
				tran = self.stack.createClientTransaction(invite)
				print "sending INVITE"
				tran.sendRequest()

		elif self.state == STATE_INVITE:

			pass
		elif self.state == STATE_DEREGISTRATION:
			print "incoming message in deregistration state"
		else:
			print "unknown state"

### main ##############################

sipClient = SipClient()
sipClient.run()

