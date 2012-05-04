#!/usr/bin/python

import sys
import time
import copy
import os
import threading
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener, DigestAuthenticator
from accountmanager import *

def user2Uri(user):
	result = SipUri()
	result.setScheme(Uri.SCHEME_SIP)
	result.setUser(user.getUserName())
	result.setHost(user.getSipDomain())
	return result

def user2Address(user):
	result = SipAddress()
	result.setDisplayName(user.getDisplayName())
	result.setUri(user2Uri(user))
	return result

OUTBOUND_PROXY = "22.10.31.72:5060"

localHop1 = Hop("64.9.169.27:60001", Sip.TRANSPORT_UDP)
localHop2 = Hop("64.9.169.28:60002", Sip.TRANSPORT_UDP)

accounts = AccountManager()
accounts.loadFromXml('users.xml')
user1 = accounts.getUserByName('ITSY000001')
user2 = accounts.getUserByName('ITSY000002')

STATE_START = "start"
STATE_REGISTRATION = 'registration'
STATE_REGISTERED = 'registered'
STATE_REGFAILED = 'registration_failed'
STATE_DEREGISTRATION = 'deregistration'
STATE_DEREGISTERED = 'deregistered'
STATE_DEREGFAILED = 'deregistration_failed'
STATE_INVITE = 'invite'
STATE_FINISHED = 'finished'

class SipClient(SipListener):

	def __init__(self, localHop1, localHop2, user1, user2):
		self.stack = SipStack({
			SipStack.PARAM_STACK_NAME: os.path.abspath(__file__),
			SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY,
			SipStack.PARAM_CREATE_TRANSACTIONS: True})
		self.msgFactory = MessageFactory()
		self.headerFactory = HeaderFactory()
		self.localHop1 = localHop1
		self.localHop2 = localHop2
		self.user1 = user1
		self.user1.state = STATE_START
		self.user1.user1Addr = user2Address(user1)
		self.user1.hop = localHop1
		self.user2 = user2
		self.user2Addr = user2Address(user2)
		self.user2.state = STATE_START
		self.user2.hop = localHop2
		self.users = [self.user1, self.user2]
		self.onStateChangedlock = threading.Lock()

	def run(self):
		try:
			self.stack.start()
			udpListeningPoint1 = SipListeningPoint(self.stack, self.user1.hop.getHost(), self.user1.hop.getPort(), Sip.TRANSPORT_UDP);
			udpListeningPoint2 = SipListeningPoint(self.stack, self.user2.hop.getHost(), self.user2.hop.getPort(), Sip.TRANSPORT_UDP);
			self.stack.addListeningPoint(udpListeningPoint1)
			self.stack.addListeningPoint(udpListeningPoint2)
			self.stack.addSipListener(self)
			authenticator = DigestAuthenticator(self.stack, accounts)
			self.stack.addSipInterceptor(authenticator)

			self.onStateChanged()

			time.sleep(1)
		finally:
			self.stack.stop()

	def onStateChanged(self):
		self.onStateChangedlock.acquire()
		print "onStateChanged - current state is: user1=%s user2=%s" % (self.user1.state, self.user2.state)
		try:
			for user in self.users:
				if user.state == STATE_START:
					user.registerRequest = MessageFactory.createRequestRegister(user, user.hop)
					tran = self.stack.createClientTransaction(user.registerRequest)
					print "sending REGISTER for user %s" % user.getUserName()
					user.state = STATE_REGISTRATION
					tran.sendRequest()

				elif user.state == STATE_REGISTERED:
					print "registration finished for user %s" % user.getUserName()

					if self.user1.state == STATE_REGISTERED and self.user2.state == STATE_REGISTERED:
						print "starting session" 

					#dereg = MessageFactory.createRequestDeRegister(user.registerRequest)
					#tran = self.stack.createClientTransaction(dereg)
					#print "sending deREGISTER for user %s" % user.getUserName()
					#user.state = STATE_DEREGISTRATION
					#tran.sendRequest()

				elif user.state == STATE_DEREGISTERED:
					print "de-registration finished for user %s" % user.getUserName()
					user.state = STATE_FINISHED

				elif user.state == STATE_REGFAILED:
					print "registration failed for user %s" % user.getUserName()
					user.state = STATE_FINISHED

				elif user.state == STATE_DEREGFAILED:
					print "de-registration failed for user %s" % user.getUserName()
					user.state = STATE_FINISHED


		finally:
			self.onStateChangedlock.release()

	def processResponse(self, responseEvent):
		response = responseEvent.getResponse()
		print "incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase())

		fromHeader = response.getHeaderByType(SipFromHeader)
		userName = fromHeader.getAddress().getUri().getUser()
		print "from user is %s" % userName

		for user in self.users:
			if user.state == STATE_REGISTRATION:
				if response.getStatusCode() >= 200 and response.getStatusCode() < 299:
					user.state = STATE_REGISTERED 
					self.onStateChanged()
				elif response.getStatusCode() > 300 and response.getStatusCode() < 299:
					user.state = STATE_REGFAILED
					self.onStateChanged()

			elif user.state == STATE_DEREGISTRATION:
				if response.getStatusCode() >= 200 and response.getStatusCode() < 299:
					user.state = STATE_DEREGISTERED 
					self.onStateChanged()
				elif response.getStatusCode() > 300 and response.getStatusCode() < 299:
					user.state = STATE_DEREGFAILED
					self.onStateChanged()
			else:
				print "unknown state"

### main ##############################

sipClient1 = SipClient(localHop1, localHop2, user1, user2)
sipClient1.run()

