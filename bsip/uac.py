#!/usr/bin/python

import logging
import time
import cmd

import message
import stack
import user
import auth
import transaction
from bsip.sip import Sip

class UAC(stack.Module):
    """UAC module"""

    def __init__(self, user):
        stack.Module.__init__(self)
        self.priority = stack.Module.PRIO_DIALOG_USAGE
        self.user = user
        self.digestAuthenticator = auth.DigestAuthenticator(user)

    def getId(self):
        return 'reg'

    def register(self):
        regRequest = message.MessageFactory.createRequestRegister(self.user.getAddress())
        trans = transaction.TranClientNonInvite(self.stack, self, regRequest, self.user.getProxy())
        trans.sendRequest()
       
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

    def onTranState(self, tran):
        print 'Transaction state have changed to ', tran.state.getId()


