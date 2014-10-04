#!/usr/bin/python

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
import bsip.uac
import bsip.transaction
#from bsip.sip import Sip

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
    #tranUdp = bsip.stack.TransportUdp(stack, '64.197.0.1', 5060)
    #tranTcp = bsip.stack.TransportTcp(stack, '192.168.0.104', 5060)

    user = bsip.user.User()
    userAddr = bsip.message.SipAddress()
    userAddr.setDisplayName('ITLL000001')
    user.setAddress(userAddr)
    user1Uri = bsip.message.SipUri()
    user1Uri.setScheme(bsip.message.Uri.SCHEME_SIP)
    user1Uri.setUser('ITLL000001')
    user1Uri.setHost('brn56.iit.ims')
    user.setUri(user1Uri)
    #self.user.setProxy(('127.0.0.1', 5060))
    user.setProxy(('21.56.31.72', 5060))

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
    user.setDigestUser("michal.nezerka")
    user.setDigestPassword("blueboy76")

    uac = bsip.uac.UAC(user)
    stack.registerModule(uac)
    stack.registerModule(bsip.stack.ModuleSipLog())
    stack.registerModule(bsip.transaction.TransactionMgr())

    uac.register()

    while True:

        stack.loop()
        time.sleep(0.1)

        if uac.getState() == bsip.uac.UAC.STATE_REGISTERED:
            uac.deRegister()     
        elif uac.getState() == bsip.uac.UAC.STATE_NOT_REGISTERED:
            break

