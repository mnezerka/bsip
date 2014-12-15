#!/usr/bin/python

# sip client

# tip: http://pymotw.com/2/cmd/

import logging
import threading
import time
import cmd
import sys

import bsip.message
import bsip.stack
import bsip.user
import bsip.auth
import bsip.uac
import bsip.transaction
from bsip.accountmanager import AccountManager

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

    am = AccountManager()
    am.loadFromXml('users.xml')

    bob = am.getUserByUri(bsip.message.SipUri('sip:bob@asterisk'))  
    alice = am.getUserByUri(bsip.message.SipUri('sip:alice@asterisk'))  
    if bob is None or alice is None:
        raise("Unknown user")

    bobTranUdp = bsip.stack.TransportUdp(stack, bob.getNetAddr())
    aliceTranUdp = bsip.stack.TransportUdp(stack, alice.getNetAddr())

    bobUac = bsip.uac.UAC(bob)
    aliceUac = bsip.uac.UAC(alice)
    stack.registerModule(bobUac)
    stack.registerModule(aliceUac)

    stack.registerModule(bsip.stack.ModuleSipLog())
    stack.registerModule(bsip.transaction.TransactionMgr())

    print "Registering users", bob, alice
    bobUac.register()
    aliceUac.register()

    while True:
        stack.loop()
        time.sleep(0.1)

        if bobUac.getState() == bsip.uac.UAC.STATE_FAILED:
            lr = bobUac.getLastResponse()
            print "Failed (%d %s)" % (lr.getStatusCode(), lr.getReasonPhrase())
            break
        if aliceUac.getState() == bsip.uac.UAC.STATE_FAILED:
            lr = aliceUac.getLastResponse()
            print "Failed (%d %s)" % (lr.getStatusCode(), lr.getReasonPhrase())
            break

        if bobUac.getState() == bsip.uac.UAC.STATE_REGISTERED:
            print "User %s registered" % str(bob)
        if aliceUac.getState() == bsip.uac.UAC.STATE_REGISTERED:
            print "User %s registered" % str(alice)

        if aliceUac.getState() == bsip.uac.UAC.STATE_REGISTERED and aliceUac.getState() == bsip.uac.UAC.STATE_REGISTERED:
            break
             
    print "Finished"





