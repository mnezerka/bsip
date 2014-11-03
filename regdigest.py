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

    #user = am.getUserByUri(bsip.message.SipUri('sip:michal.nezerka@iptel.org'))  
    user = am.getUserByUri(bsip.message.SipUri('sip:bob@asterisk'))  
    if user is None:
        raise("Unknown user")

    tranUdp = bsip.stack.TransportUdp(stack, user.getNetAddr())

    uac = bsip.uac.UAC(user)
    stack.registerModule(uac)
    stack.registerModule(bsip.stack.ModuleSipLog())
    stack.registerModule(bsip.transaction.TransactionMgr())

    #aliceAddr  = bsip.message.SipAddress('Alice <sip:alice@atlanta.com>')
    aliceAddr  = bsip.message.SipAddress('<sip:+420119107@iptel.org>')
    aliceAddr  = bsip.message.SipAddress('<sip:530333584@sip.fayn.cz>')

    print "Registering user", user
    uac.register()

    while True:
        stack.loop()
        time.sleep(0.1)
        if uac.getState() == bsip.uac.UAC.STATE_REGISTERED:
            print "User registered"
            break
        elif uac.getState() == bsip.uac.UAC.STATE_NOT_REGISTERED:
            print "User not registered"
            break
        elif uac.getState() == bsip.uac.UAC.STATE_FAILED:
            lr = uac.getLastResponse()
            print "Failed (%d %s)" % (lr.getStatusCode(), lr.getReasonPhrase())
            break

    print "Finished"

