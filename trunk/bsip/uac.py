#!/usr/bin/python

import logging
import time
import cmd

import message
import stack
import user
import auth
from bsip.sip import Sip

class UAC(stack.Module):
    """UAC module"""

    def __init__(self, user):
        self.priority = stack.Module.PRIO_DIALOG_USAGE
        self.user = user
        self.digestAuthenticator = auth.DigestAuthenticator(user)

    def getId(self):
        return 'reg'

    def register(self, user):
        txData = stack.SipTxData()
        txData.msg = message.MessageFactory.createRequestRegister(user.getAddress())
        txData.transport = self.stack.acquireTransport(Sip.TRANSPORT_UDP)
        txData.dest = user.getProxy() 
        self.stack.sendStateless(txData)
        self.origRequest = txData.msg

    # Called on rx response
    def onRxResponse(self, rxData):
        print 'Received SIP response: %d %s' % (rxData.msg.getStatusCode(), rxData.msg.getReasonPhrase())

        # if received response is of type "some authorization required", we need to generate new
        # request with computed authentication values 
        if rxData.msg.getStatusCode() in [Sip.RESPONSE_UNAUTHORIZED, Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]:
            request = handleChallenge(rxData.msg, self.origRequest)
            txData = stack.SipTxData()
            txData.transport = self.stack.acquireTransport(sip.Sip.TRANSPORT_UDP)
            txData.dest = user.getProxy() 
            self.stack.sendStateless(txData)
        else:
            print "finished"

        return False

