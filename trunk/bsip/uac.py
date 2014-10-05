#!/usr/bin/python

import logging
import time
import cmd

import message
import stack
import user
import auth
import transaction
from transaction import Transaction
from sip import Sip, SipException

class UAC(stack.Module):
    """UAC module"""

    LOGGER_NAME = 'BSip.UAC'

    STATE_NOT_REGISTERED = 'not-registered'
    STATE_REGISTERING = 'registering'
    STATE_REGISTERED = 'registered'
    STATE_DEREGISTERING = 'de-registering'
    STATE_CALLING = 'calling'
    STATE_IN_CALL = 'calling'

    def __init__(self, user):
        stack.Module.__init__(self)
        self.priority = stack.Module.PRIO_DIALOG_USAGE
        self.user = user
        self.digestAuthenticator = auth.DigestAuthenticator(user)
        self.state = UACNotRegistered(self)
        self.logger = logging.getLogger(self.LOGGER_NAME)

    def getId(self):
        """Returns module identification"""
        return 'uac'

    def getState(self):
        return self.state.getId()

    def setState(self, newState):
        self.logger.debug('Changing state: %s -> %s' % (self.state.getId(), newState.getId()))
        self.state = newState

    def register(self):
        self.state.register()

    def deRegister(self):
        self.state.deRegister()

    def call(self, termUri):
        assert isinstance(termUri, message.SipAddress)
        self.state.call(termUri)

    def onTranState(self, tran):
        self.logger.debug('Transaction state have changed to ' + tran.state.getId())
        self.state.onTranState(tran)

class UACState():
    """Base class for all UAC states"""

    def __init__(self, uac):
        self.uac = uac

    def getId(self):
        return 'base'

    def register(self):
        raise SipException('Cannot register in this state')

    def deRegister(self):
        raise SipException('Cannot de-register in this state')

    def call(self, termUri):
        raise SipException('Cannot call in this state')

    def onTranState(self, tran):
        pass
         
class UACNotRegistered(UACState):
    """User is not registered"""

    def getId(self):
        return UAC.STATE_NOT_REGISTERED

    def register(self):
        self.uac.logger.info('Registering user')
        regRequest = message.MessageFactory.createRequestRegister(self.uac.user.getAddress())
        trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest, self.uac.user.getProxyAddr())
        trans.sendRequest()
        self.uac.setState(UACRegistering(self.uac))
         
class UACRegistering(UACState):
    """User is being registered"""

    def getId(self):
        return UAC.STATE_REGISTERING

    def onTranState(self, tran):
        if tran.state.getId() == Transaction.STATE_COMPLETED:
            self.uac.logger.debug("transaction completed with sip status code: %d" % tran.getLastStatusCode())

            # check if authentication is required
            if tran.getLastStatusCode() in [Sip.RESPONSE_UNAUTHORIZED, Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]: 
                # response must be challenged for authentication data and new request must be sent
                try:
                    self.uac.digestAuthenticator.handleChallenge(tran.lastResponse)
                    # create new request with authentication data
                    regRequest2 = message.MessageFactory.duplicateMessage(tran.originalRequest)
                    self.uac.digestAuthenticator.setAuthenticationHeaders(regRequest2)
                    trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest2, self.uac.user.getProxyAddr())
                    trans.sendRequest()
                except SipException:
                    self.uac.logger.debug('Authehtication failed')
                    self.uac.setState(UACNotRegistered(self.uac))
            elif tran.getLastStatusCode() == Sip.RESPONSE_OK:
                self.uac.setState(UACRegistered(self.uac))
            else:
                SipException('Unexpected reponse code: %d' % tran.getLastStatusCode())

class UACRegistered(UACState):
    """User is registered"""

    def getId(self):
        return UAC.STATE_REGISTERED

    def deRegister(self):
        deRegRequest = message.MessageFactory.createRequestRegister(self.uac.user.getAddress())
        expiresHeader = deRegRequest.getHeaderByType(message.ExpiresHeader)
        expiresHeader.setExpires(0)
        trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, deRegRequest, self.uac.user.getProxyAddr())
        self.uac.digestAuthenticator.setAuthenticationHeaders(deRegRequest)
        trans.sendRequest()
        self.uac.setState(UACDeRegistering(self.uac))

    def call(self, termUri):
        inviteRequest = message.MessageFactory.createRequestInvite(self.uac.user, termUri)
        trans = transaction.TranClientInvite(self.uac.stack, self.uac, inviteRequest, self.uac.user.getProxyAddr())
        self.uac.digestAuthenticator.setAuthenticationHeaders(inviteRequest)
        trans.sendRequest()
        self.uac.setState(UACCalling(self.uac))

class UACDeRegistering(UACState):
    """User is being deregistered"""

    def getId(self):
        return UAC.STATE_DEREGISTERING

    def onTranState(self, tran):
        if tran.state.getId() == Transaction.STATE_COMPLETED:
            self.uac.logger.debug("transaction completed with sip status code: %d" % tran.getLastStatusCode())

            # check if authentication is required
            if tran.getLastStatusCode() in [Sip.RESPONSE_UNAUTHORIZED, Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]: 
                # response must be challenged for authentication data and new request must be sent
                try:
                    self.uac.digestAuthenticator.handleChallenge(tran.lastResponse)
                    # create new request with authentication data
                    deRegRequest2 = message.MessageFactory.duplicateMessage(tran.originalRequest)
                    self.uac.digestAuthenticator.setAuthenticationHeaders(deRegRequest2)
                    trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, deRegRequest2, self.uac.user.getProxyAddr())
                    trans.sendRequest()
                except SipException:
                    self.uac.logger.debug('Authehtication failed')
                    self.uac.setState(UACRegistered(self.uac))
            elif tran.getLastStatusCode() == Sip.RESPONSE_OK:
                self.uac.setState(UACNotRegistered(self.uac))
            else:
                SipException('Unexpected reponse code: %d' % tran.getLastStatusCode())

class UACCalling(UACState):
    """User is calling"""

    def getId(self):
        return UAC.STATE_CALLING

    def onTranState(self, tran):
        if tran.state.getId() == Transaction.STATE_COMPLETED:
            self.uac.logger.debug("transaction completed with sip status code: %d" % tran.getLastStatusCode())

            # check if authentication is required
            if tran.getLastStatusCode() in [Sip.RESPONSE_UNAUTHORIZED, Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]: 
                # response must be challenged for authentication data and new request must be sent
                try:
                    self.uac.digestAuthenticator.handleChallenge(tran.lastResponse)
                    # create new request with authentication data
                    inviteRequest2 = message.MessageFactory.duplicateMessage(tran.originalRequest)
                    self.uac.digestAuthenticator.setAuthenticationHeaders(inviteRequest2)
                    trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, inviteRequest2, self.uac.user.getProxyAddr())
                    trans.sendRequest()
                except SipException:
                    self.uac.logger.debug('Authehtication failed')
                    self.uac.setState(UACNotRegistered(self.uac))
            elif tran.getLastStatusCode() == Sip.RESPONSE_OK:
                self.uac.setState(UACInCall(self.uac))
            else:
                SipException('Unexpected reponse code: %d' % tran.getLastStatusCode())

        elif tran.state.getId() == Transaction.STATE_TERMINATED:
            self.uac.logger.debug("transaction terminated with sip status code: %d" % tran.getLastStatusCode())

class UACInCall(UACState):
    """User is in call"""

    def getId(self):
        return UAC.STATE_IN_CALL


