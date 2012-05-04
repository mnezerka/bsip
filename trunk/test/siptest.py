#!/usr/bin/python

import sys
import time
import os
from sipstack import SipStack, SipListeningPoint, SipListener, DigestAuthenticator
import accountmanager

class SipUe(SipListener):

	STATE_START = "start"
	STATE_REGISTRATION = 'registration'
	STATE_REGISTERED = 'registered'
	STATE_REGFAILED = 'registration_failed'
	STATE_INVITE = 'invite'
	STATE_CALLING = 'calling'
	STATE_INVITED = 'invited'
	STATE_SESSION = 'session'
	STATE_CALLFAILED = 'call_failed'
	STATE_CONNECTED = 'connected'
	STATE_DEREGISTER = 'deregister'
	STATE_DEREGISTRATION = 'deregistration'
	STATE_DEREGISTERED = 'deregistered'
	STATE_DEREGFAILED = 'deregistration_failed'
	STATE_FINISHED = 'finished'

	def __init__(self, user, sipStack):
		SipListener.__init__(self)
		if not isinstance(user, accountmanager.User) or not isinstance(sipStack, SipStack):
			raise Exception("Invalid parameter(s)")

		self._user = user 
		self._state = None
		self._sipStack = sipStack

	def getUser(self):
		return self._user

	def getSipStack(self):
		return self._sipStack

	def setState(self, newState):
		self.logMsg("changing state %s => %s" % (self._state, newState))
		self._state = newState

	def getState(self):
		return self._state

	def getId(self):
		return str(self._user.getAddress().getUri())

	def logMsg(self, msg):
		print "SipUe:%s - %s" % (self.getId(), msg)

	def run(self):
		pass		

class SipTest(SipListener):

	def __init__(self, sipStack):
		self.stack = sipStack
		self._ues = [] 

	def addUe(self, ue):
		self._ues.append(ue)

	def getSipStack(self):
		return self.stack

	def run(self):
		try:
			self.stack.start()
			# create listening points for each ue
			for ue in self._ues:
				listeningPoint = SipListeningPoint(self.stack, ue.getUser().getHop());
				listeningPoint.addSipListener(ue)
				self.stack.addListeningPoint(listeningPoint)

			for ue in self._ues:
				ue.run()	

			time.sleep(5)
		finally:
			self.stack.stop()

  def loadFromXml(self, filePath):
    '''Load configuration from xml file'''
    try:
        xmlDoc = minidom.parse(filePath)
    except Exception:
        print("Error: processing (parsing) config xml file failed:", filePath)
        raise
    self._parseFromXmlDoc(xmlDoc)   

  def _parseFromXmlDoc(self, xmlDoc):
    testbeds = xmlDoc.getElementsByTagName("testbeds")
    for tbNode in testbeds:
      for accountEl in accountNode.childNodes:
        if accountEl.nodeType == accountEl.ELEMENT_NODE and accountEl.tagName.lower() == "account":
          user = User()
          userAddr = sipmessage.SipAddress()  
          user.setAddress(userAddr)
          for userEl in accountEl.childNodes:
            if userEl.nodeType != accountEl.ELEMENT_NODE:
              continue
            if userEl.tagName.lower() == "sip-uri":
              uri = sipmessage.AddressFactory.createUri(_xmlNodeGetText(userEl))
              userAddr.setUri(uri)
            if userEl.tagName.lower() == "display-name":
              userAddr.setDisplayName(_xmlNodeGetText(userEl))
            if userEl.tagName.lower() == "digest-user":
              user.setDigestUser(_xmlNodeGetText(userEl))
            if userEl.tagName.lower() == "digest-password":
              user.setDigestPassword(_xmlNodeGetText(userEl))
            if userEl.tagName.lower() == "net-addr":
              userHop = sipmessage.Hop(_xmlNodeGetText(userEl))
              userHop.setTransport(sipmessage.Sip.TRANSPORT_UDP)
              user.setHop(userHop)

          if not user.getUri() is None:
            self.add(user)


