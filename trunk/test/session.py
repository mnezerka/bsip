#!/usr/bin/python

import sys
import time
import copy
import os
from collections import deque
from sipmessage import *
from sipstack import SipStack, SipListeningPoint, SipListener, DigestAuthenticator
from accountmanager import *
from siptest import SipTest, SipUe

class SyncSession(object):
    #def __init__(self, ue1, ue2):
    #   self._ue1 = ue1
    #   self._ue2 = ue2
    def __init__(self):
        self._registered = []
        self._events = deque()

    def onStateChange(self, ue):
        print "state change, ue: %s, state=%s" % (ue.getId(), ue.getState())
        if ue.getState() == SipUe.STATE_REGISTERED:
            if ue not in self._registered:
                self._registered.append(ue)
            if len(self._registered) == 2:
                print "all are registered, starting session"
                for ueInCall in self._registered:
                    if isinstance(ueInCall, SipUeSessionOrig):
                        ueInCall.setState(SipUe.STATE_INVITE)

        if ue.getState() == SipUe.STATE_CONNECTED:
            print "all are registered, starting deregistration"
            for ueToDereg in self._registered:
                ueToDereg.setState(SipUe.STATE_DEREGISTER)

class SipUeSessionOrig(SipUe):
    def __init__(self, user, sipStack, sync, toBeCalled):
        SipUe.__init__(self, user, sipStack)
        self._sync = sync
        self._toBeCalled = toBeCalled

    def run(self):
        self.setState(SipUe.STATE_START)


    def processResponse(self, responseEvent):
        response = responseEvent.getResponse()
        self.logMsg("incoming response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase()))

        fromHeader = response.getHeaderByType(SipFromHeader)
        toHeader = response.getHeaderByType(SipToHeader)
        userName = fromHeader.getAddress().getUri().getUser()

        if self.getState() == SipUe.STATE_REGISTRATION:
            if response.getStatusCode() >= 200 and response.getStatusCode() < 299:
                self.setState(SipUe.STATE_REGISTERED)
            elif response.getStatusCode() >= 300:
                self.setState(SipUe.STATE_REGFAILED)

        if self.getState() == SipUe.STATE_CALLING:
            if response.getStatusCode() >= 100 and response.getStatusCode() < 199:
                self.logMsg("provisional response (code %d) received" % response.getStatusCode())
            elif response.getStatusCode() >= 200 and response.getStatusCode() < 299:
                # store remote to tag that is part of established dialog
                inviteToHeader = self.invite.getHeaderByType(SipToHeader)
                inviteToHeader.setTag(toHeader.getTag())
                self.setState(SipUe.STATE_SESSION)
            elif response.getStatusCode() >= 300:
                self.setState(SipUe.STATE_CALLFAILED)

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
            self.registerRequest = MessageFactory.createRequestRegister(self._user.getAddress(), self._user.getHop())
            tran = self.getSipStack().createClientTransaction(self.registerRequest)
            self.logMsg("sending REGISTER")
            self.setState(SipUe.STATE_REGISTRATION)
            tran.sendRequest()

        elif newState == SipUe.STATE_REGISTERED:
            self.logMsg("registration finished")
            self._sync.onStateChange(self)

        elif newState == SipUe.STATE_INVITE:
            self.invite = MessageFactory.createRequestInvite(self.getUser().getAddress(), self._toBeCalled, self.getUser().getHop())
            tran = self.getSipStack().createClientTransaction(self.invite)
            self.logMsg("sending INVITE")
            self.setState(SipUe.STATE_CALLING)
            tran.sendRequest()

        elif newState == SipUe.STATE_SESSION:
            self.logMsg("session is established")
            ackRequest = MessageFactory.createRequestAck(self.invite)
            self.logMsg("sending ACK")
            self.getSipStack().sendRequest(ackRequest)
    
        elif newState == SipUe.STATE_DEREGISTER:
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

class SipUeSessionTerm(SipUe):
    def __init__(self, user, sipStack, sync):
        SipUe.__init__(self, user, sipStack)
        self._sync = sync

    def run(self):
        self.setState(SipUe.STATE_START)

    def processRequest(self, requestEvent):
        request = requestEvent.getRequest()
        self.logMsg("incoming request: %s" % (request.getMethod()))

        if self.getState() == SipUe.STATE_REGISTERED:
            if request.getMethod() == SipRequest.METHOD_INVITE:
                self.inviteRequestEvent = requestEvent
                self.setState(SipUe.STATE_INVITED)

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
            self.registerRequest = MessageFactory.createRequestRegister(self._user.getAddress(), self._user.getHop())
            tran = self.getSipStack().createClientTransaction(self.registerRequest)
            self.logMsg("sending REGISTER")
            self.setState(SipUe.STATE_REGISTRATION)
            tran.sendRequest()

        elif newState == SipUe.STATE_REGISTERED:
            self.logMsg("registration finished")
            self._sync.onStateChange(self)

        elif newState == SipUe.STATE_INVITED:
            self.logMsg("invited")
            inviteServerTransaction = self.inviteRequestEvent.getServerTransaction()
            dialog = self.getSipStack().createDialog(inviteServerTransaction.getOriginalRequest())

            #responseOk = MessageFactory.createResponse(SipResponse.RESPONSE_OK, inviteServerTransaction.getOriginalRequest())
            #dialog = self.getSipStack().createDialog(responseOk)

            #toHeader = responseOk.getHeaderByType(SipToHeader);
            #tag = SipUtils.generateTag()
            #toHeader.setTag(tag)
            #dialog = self.getSipStack().createDialog(responseOk)
            #self.logMsg("sending 200 OK")
            #inviteServerTransaction.sendResponse(responseOk)

        elif newState == SipUe.STATE_DEREGISTER:
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

### main ##############################

OUTBOUND_PROXY = "22.10.31.72:5060" # tb310
OUTBOUND_PROXY = "22.38.31.72:5060" # tb338
OUTBOUND_PROXY = "127.0.0.1:5060"

# user accounts
accounts = AccountManager()
accounts.loadFromXml('users_blue.xml')
user1 = accounts.getUserByUri(SipUri("sip:blue1@blue.home.net"))
user2 = accounts.getUserByUri(SipUri("sip:blue2@blue.home.net"))

# sip stack
sipStack = SipStack({
    SipStack.PARAM_STACK_NAME: os.path.abspath(__file__),
    SipStack.PARAM_OUTBOUND_PROXY: OUTBOUND_PROXY,
    SipStack.PARAM_CREATE_TRANSACTIONS: True,
    SipStack.PARAM_CREATE_DIALOGS: True})

# sync class
sync = SyncSession()

# user equipments
ue1 = SipUeSessionOrig(user1, sipStack, sync, user2.getAddress())
ue2 = SipUeSessionTerm(user2, sipStack, sync)

# test
sipTest = SipTest(sipStack)
sipTest.addUe(ue1)
sipTest.addUe(ue2)
sipTest.run()


