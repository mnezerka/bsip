#!/usr/bin/python

import sys
import time
import copy
import os
import threading
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener, DigestAuthenticator
from accountmanager import *
from siptest import SipTest, SipUe

class SipUeRegDereg(SipUe):

  def __init__(self, user, sipStack):
    SipUe.__init__(self, user, sipStack)
    self._count = 1
    self._processed = 0;

  def setCount(self, count):
    self._count = count;

  def run(self):
    self.logMsg("starting for %d registrations" % self._count)
    self.setState(SipUe.STATE_START)

  def processResponse(self, responseEvent):
    response = responseEvent.getResponse()
    self.logMsg("incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase()))

    fromHeader = response.getHeaderByType(SipFromHeader)
    userName = fromHeader.getAddress().getUri().getUser()

    if self.getState() == SipUe.STATE_REGISTRATION:
      if response.getStatusCode() >= 200 and response.getStatusCode() < 299:
        self.setState(SipUe.STATE_REGISTERED)
      elif response.getStatusCode() >= 300:
        self.setState(SipUe.STATE_REGFAILED)

    elif self.getState() == SipUe.STATE_DEREGISTRATION:
      if response.getStatusCode() >= 200 and response.getStatusCode() < 299:
        self.setState(SipUe.STATE_DEREGISTERED)
      elif response.getStatusCode() >= 300:
        self.setState(SipUe.STATE_DEREGFAILED)
    else:
      self.logMsg("unknown state")


  def setState(self, newState):

    SipUe.setState(self, newState)

    if newState == SipUe.STATE_START:
      self.logMsg("starting registration %d of %d" % (self._processed, self._count))
      self.registerRequest = MessageFactory.createRequestRegister(self._user.getAddress(), self._user.getHop())
      # create authorization header (special for our IMS) 
#      authHeader = AuthorizationHeader()
#      authHeader.setScheme('Digest')
#      authHeader.setUserName(self._user.getDigestUser())
#      authHeader.setRealm(self._user.getUri().getHost())
#      authHeader.setUri(str(self.registerRequest.getRequestUri()))
#      authHeader.setNonce('')
#      authHeader.setResponse('')
#      self.registerRequest.addHeader(authHeader)
      tran = self.getSipStack().createClientTransaction(self.registerRequest)
      self.logMsg("sending REGISTER")
      self.setState(SipUe.STATE_REGISTRATION)
      tran.sendRequest()

    elif newState == SipUe.STATE_REGISTERED:
      self.logMsg("registration finished")
      dereg = MessageFactory.createRequestDeRegister(self.registerRequest)
      tran = self.getSipStack().createClientTransaction(dereg)
      self.logMsg("sending deREGISTER")
      self.setState(SipUe.STATE_DEREGISTRATION)
      tran.sendRequest()

    elif newState == SipUe.STATE_DEREGISTERED:
      self.logMsg("de-registration finished")
      self.setState(SipUe.STATE_FINISHED)

    elif newState == SipUe.STATE_REGFAILED:
      self.logMsg("registration failed")
      self.setState(SipUe.STATE_FINISHED)

    elif newState == SipUe.STATE_DEREGFAILED:
      self.logMsg("de-registration failed")
      self.setState(SipUe.STATE_FINISHED)

    elif newState == SipUe.STATE_FINISHED:
      self._processed += 1;
      self.logMsg("finished registration %d of %d" % (self._processed, self._count))
      if (self._processed < self._count):
        self.setState(SipUe.STATE_START) 

### main ##############################

OUTBOUND_PROXY = "22.10.31.72:5060" # tb310
OUTBOUND_PROXY = "22.38.31.72:5060" # tb338
OUTBOUND_PROXY = "22.56.31.72:5060" # tb356
OUTBOUND_PROXY = "127.0.0.1:5060"

# user accounts
accounts = AccountManager()
accounts.loadFromXml('users_blue.xml')
user1 = accounts.getUserByUri(SipUri("sip:blue1@blue.home.net"))
#user2 = accounts.getUserByUri(SipUri("sip:ITSY000002@brn38.iit.ims"))

# sip stack
sipStack = SipStack({
  SipStack.PARAM_STACK_NAME: os.path.abspath(__file__),
  SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY,
  SipStack.PARAM_CREATE_TRANSACTIONS: True})

# enable digest authentication
authenticator = DigestAuthenticator(sipStack, accounts)
sipStack.addSipInterceptor(authenticator)

# user equipments
ue1 = SipUeRegDereg(user1, sipStack)
ue1.setCount(10)

# test
sipTest = SipTest(sipStack)
sipTest.addUe(ue1)
sipTest.run()


