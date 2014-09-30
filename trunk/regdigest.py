# sip client

# tip: http://pymotw.com/2/cmd/

import logging
import threading
import time
import cmd

import bsip.message
import bsip.stack
import bsip.user
import bsip.auth
from bsip.sip import Sip

class SipModuleRegistration(bsip.stack.Module):
    """Registration module"""

    def __init__(self):
        self.priority = bsip.stack.Module.PRIO_DIALOG_USAGE
        self.origRequest
        self.digestAuthenticator = bsip.auth.DigestAuthenticator()

    def getId(self):
        return 'reg'

    def register(self, user):
        txData = bsip.stack.SipTxData()
        txData.msg = bsip.message.MessageFactory.createRequestRegister(user.getAddress())
        txData.transport = self.stack.acquireTransport(bsip.sip.Sip.TRANSPORT_UDP)
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
            txData = bsip.stack.SipTxData()
            txData.transport = self.stack.acquireTransport(bsip.sip.Sip.TRANSPORT_UDP)
            txData.dest = user.getProxy() 
            self.stack.sendStateless(txData)
        else:
            print "finished"

        return False

if __name__ == '__main__':
        # initialize logging
        logger = logging.getLogger('BSip')
        logger.setLevel(logging.DEBUG)
        h = logging.FileHandler(filename='bsip.log', mode='w')
        h.setLevel(logging.DEBUG)
        f = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%d/%m/%Y %H:%M:%S')
        h.setFormatter(f)
        logger.addHandler(h)
        logger.debug('Logging initialized')

        stack = bsip.stack.SipStack()

        #self.tranUdp = stack.TransportUdp(self.stack, '127.0.0.1', 5060)
        #self.tranLoopback = stack.TransportLoopback(stack)
        tranUdp = bsip.stack.TransportUdp(stack, '192.168.0.104', 5060)
        #tranTcp = bsip.stack.TransportTcp(stack, '192.168.0.104', 5060)

        regModule = SipModuleRegistration()
        stack.registerModule(regModule)
        stack.registerModule(bsip.stack.ModuleSipLog())

        user = bsip.user.User()
        userAddr = bsip.message.SipAddress()
        userAddr.setDisplayName('Michal Nezerka')
        user.setAddress(userAddr)
        user1Uri = bsip.message.SipUri()
        user1Uri.setScheme(bsip.message.Uri.SCHEME_SIP)
        user1Uri.setUser("michal.nezerka")
        user1Uri.setHost("iptel.org")
        user.setUri(user1Uri)
        #self.user.setProxy(('127.0.0.1', 5060))
        user.setProxy(('sip.iptel.org', 5060))
        regModule.register(user)

        while True:
            stack.loop()
            time.sleep(0.1)


