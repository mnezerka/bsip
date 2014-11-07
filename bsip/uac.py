import logging
import time
import cmd

import message
import stack
import user
import auth
import transaction
from transaction import Transaction
from sip import Sip, SipException, SipUtils

class UAC(stack.Module):
    """UAC module"""

    LOGGER_NAME = 'BSip.UAC'

    STATE_NOT_REGISTERED = 'not-registered'
    STATE_REGISTERING = 'registering'
    STATE_AUTH  = 'auth'
    STATE_FAILED = 'failed'
    STATE_REGISTERED = 'registered'
    STATE_DEREGISTERING = 'de-registering'
    STATE_CALLING = 'calling'
    STATE_IN_CALL = 'in-call'

    def __init__(self, user):
        stack.Module.__init__(self)
        self.priority = stack.Module.PRIO_DIALOG_USAGE
        self.user = user
        self.digestAuthenticator = auth.DigestAuthenticator(user)
        self.state = UACNotRegistered(self)
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.nextStateSuccessfull = None
        self.nextStateFailed = None
        self.logger.info('Created UAC for user %s' % str(self.user))
        self.lastResponse = None

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
        self.lastResponse = tran.getLastResponse()
        self.state.onTranState(tran)

    def getLastResponse(self):
        return self.lastResponse

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

class UACFailed(UACState):
    """User is in failed state"""

    def getId(self):
        return UAC.STATE_FAILED

class UACNotRegistered(UACState):
    """User is not registered"""

    def getId(self):
        return UAC.STATE_NOT_REGISTERED

    def register(self):
        self.uac.logger.info('Registering user %s (proxy: %s)' % (str(self.uac.user.getAddress()),str(self.uac.user.getProxyAddr())))
        regRequest = message.MessageFactory.createRequestRegister(self.uac.user.getAddress())

        trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest, self.uac.user.getProxyAddr())

        trans.sendRequest()

        self.uac.nextStateSuccessfull = UACRegistered(self.uac)
        self.uac.nextStateFailed = UACNotRegistered(self.uac) 
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
                    #regRequest2.setCallId(SipUtils.generateCallIdentifier())
                    regRequest2.incCSeq()
                    self.uac.digestAuthenticator.setAuthenticationHeaders(regRequest2)
                    trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest2, self.uac.user.getProxyAddr())

                    # send auth request
                    trans.sendRequest()

                    # prepare state stransitions
                    self.uac.nextStateSuccessfull = UACRegistered(self.uac)
                    self.uac.nextStateFailed = UACFailed(self.uac) 
                    self.uac.setState(UACAuth(self.uac))

                except SipException:
                    self.uac.logger.debug('Authehtication failed')
                    self.uac.setState(UACNotRegistered(self.uac))
            elif tran.getLastStatusCode() == Sip.RESPONSE_OK:
                self.uac.setState(UACRegistered(self.uac))
            elif tran.getLastStatusCode() >= 200 and tran.getLastStatusCode() <= 699:
                self.uac.setState(UACFailed(self.uac))
            else:
                SipException('Unexpected reponse code: %d' % tran.getLastStatusCode())

class UACAuth(UACState):
    """User is being registered (auth phase)"""

    def getId(self):
        return UAC.STATE_AUTH

    def onTranState(self, tran):
        if tran.state.getId() == Transaction.STATE_COMPLETED:
            self.uac.logger.debug("transaction completed with sip status code: %d" % tran.getLastStatusCode())

            # check if authentication is required
            if tran.getLastStatusCode() == Sip.RESPONSE_OK:
                if self.uac.nextStateSuccessfull is None:
                    SipException('No state defined for successfull auth');
                self.uac.setState(self.uac.nextStateSuccessfull)
            else:
                if self.uac.nextStateFailed is None:
                    SipException('No state defined for failed auth');

                #SipException('Authentication failed, reponse code: %d' % tran.getLastStatusCode())
                self.uac.setState(self.uac.nextStateFailed)

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
                    #toTag = tran.getLastResponse().getToTag()
                    #inviteRequest2.setToTag(toTag)
                    self.uac.digestAuthenticator.setAuthenticationHeaders(inviteRequest2)
                    trans = transaction.TranClientInvite(self.uac.stack, self.uac, inviteRequest2, self.uac.user.getProxyAddr())

                    # send auth request
                    trans.sendRequest()

                    # prepare state stransitions
                    self.uac.nextStateSuccessfull = UACCalling(self.uac)
                    self.uac.nextStateFailed = UACRegistered(self.uac) 
                    self.uac.setState(UACAuth(self.uac))

                except SipException:
                    self.uac.logger.debug('Authehtication failed')
                    self.uac.setState(UACCalling(self.uac))

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

