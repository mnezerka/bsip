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

    def onTranState(self, tran):
        pass
         
class UACNotRegistered(UACState):
    """User is not registered"""

    def getId(self):
        return UAC.STATE_NOT_REGISTERED

    def register(self):
        self.uac.logger.info('Registering user')
        regRequest = message.MessageFactory.createRequestRegister(self.uac.user.getAddress())
        trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest, self.uac.user.getProxy())
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
            if tran.getLastStatusCode() in [401, 403]:
                regRequest2 = self.uac.digestAuthenticator.handleChallenge(tran.lastResponse, tran.originalRequest)
                self.uac.digestAuthenticator.onMessageSend(regRequest2)
                trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest2, self.uac.user.getProxy())
                trans.sendRequest()
            elif tran.getLastStatusCode() == 200:
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
        trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, deRegRequest, self.uac.user.getProxy())
        trans.sendRequest()
        self.uac.setState(UACDeRegistering(self.uac))

class UACDeRegistering(UACState):
    """User is being deregistered"""

    def getId(self):
        return UAC.STATE_DEREGISTERING

    def onTranState(self, tran):
        if tran.state.getId() == Transaction.STATE_COMPLETED:
            self.uac.logger.debug("transaction completed with sip status code: %d" % tran.getLastStatusCode())

            # check if authentication is required
            if tran.getLastStatusCode() in [401, 403]:
                regRequest2 = self.uac.digestAuthenticator.handleChallenge(tran.lastResponse, tran.originalRequest)
                self.uac.digestAuthenticator.onMessageSend(regRequest2)
                trans = transaction.TranClientNonInvite(self.uac.stack, self.uac, regRequest2, self.uac.user.getProxy())
                trans.sendRequest()
            elif tran.getLastStatusCode() == 200:
                self.uac.setState(UACNotRegistered(self.uac))
            else:
                SipException('Unexpected reponse code: %d' % tran.getLastStatusCode())


