# sip client

# tip: http://pymotw.com/2/cmd/

import logging
import threading
import time
import cmd

import bsip.message
import bsip.stack
import bsip.user

class SipStackThread(threading.Thread):
    LOGGER_NAME = 'sipStackThread'

    def __init__(self, sipStack):
        threading.Thread.__init__(self)
        self.__sipStack = sipStack 
        self.__running = False

    def run(self):
        self.__sipStack.start()

    def stop(self):
        self.__sipStack.stop()

class SipModuleRegistration(bsip.stack.Module):
    """Registration module"""

    def __init__(self):
        self.priority = stack.Module.PRIO_DIALOG_USAGE

    def getId(self):
        return 'reg'

    # Called on rx request
    def onRxRequest(self, rxData):
        print 'Received SIP request'
        print 'Sending SIP response'
        response = stack.MessageFactory.createResponse(200, rxData.msg)
        #txData.msg = stack.MessageFactory.createRequestRegister(user.getAddress())
        return True 

    # Called on rx response
    def onRxResponse(self, rxData):
        print 'Received SIP response'
        return False

    def register(self, user):
        print 'Registering user', user
        txData = stack.SipTxData()
        txData.msg = stack.MessageFactory.createRequestRegister(user.getAddress())
        txData.transport = self.stack.acquireTransport(stack.Sip.TRANSPORT_TCP)
        txData.dest = user.getProxy() 
        self.stack.sendStateless(txData)

class BSip(cmd.Cmd):
    """BSip command line processor"""

    prompt = 'bsip> '

    def __init__(self):
        cmd.Cmd.__init__(self)
        # initialize logging
        self.logger = logging.getLogger('BSip')
        self.logger.setLevel(logging.DEBUG)
        h = logging.FileHandler(filename='bsip.log', mode='w')
        h.setLevel(logging.DEBUG)
        f = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%d/%m/%Y %H:%M:%S')
        h.setFormatter(f)
        self.logger.addHandler(h)
        self.logger.debug('Logging initialized')

        self.stack = bsip.stack.SipStack()
        self.stackThread = SipStackThread(self.stack)
        self.stackThread.start()

        #self.tranUdp = stack.TransportUdp(self.stack, '127.0.0.1', 5060)
        self.tranLoopback = stack.TransportLoopback(self.stack)
        #self.tranUdp = stack.TransportUdp(self.stack, '192.168.0.104', 5060)
        self.tranTcp = stack.TransportTcp(self.stack, '192.168.0.104', 5060)

        self.regModule = SipModuleRegistration()
        self.stack.registerModule(self.regModule)

        self.stack.registerModule(stack.ModuleSipLog())

        self.user = bsip.user.User()
        userAddr = bsip..SipAddress()
        userAddr.setDisplayName('Bob')
        self.user.setAddress(userAddr)
        user1Uri = stack.SipUri()
        user1Uri.setScheme(stack.Uri.SCHEME_SIP)
        user1Uri.setUser("bob")
        user1Uri.setHost("beloxi.com")
        self.user.setUri(user1Uri)
        self.user.setProxy(('127.0.0.1', 5060))

        self.user = stack.User()
        userAddr = stack.SipAddress()
        userAddr.setDisplayName('Michal Nezerka')
        self.user.setAddress(userAddr)
        user1Uri = stack.SipUri()
        user1Uri.setScheme(stack.Uri.SCHEME_SIP)
        user1Uri.setUser("michal.nezerka")
        user1Uri.setHost("iptel.org")
        self.user.setUri(user1Uri)
        #self.user.setProxy(('127.0.0.1', 5060))
        self.user.setProxy(('sip.iptel.org', 5060))

    def do_greet(self, line):
        print "hello"

    def do_exit(self, line):
        self.stackThread.stop()
        """Quit BSip application"""
        return True

    def do_show(self, what):
        """Shows application configuration an, status"""
        if what == 'users':
            print 'users'
        elif what == 'status':
            print 'stack state: %d' % (self.stack.isRunning())
        elif what == 'transports':
            print 'Transports:'
            transports = self.stack.transportManager.transports
            for tId in transports:
                print tId
        elif what == 'user':
            print self.user
        else:
            print 'unknown command'

    def do_register(self, userId):
        """Register user"""
        self.regModule.register(self.user)

    def emptyline(self):
        pass

if __name__ == '__main__':
    bsip = BSip()
    try:
        bsip.cmdloop()
    except:
    #except KeyboardInterrupt:
        bsip.stack.stop() 
        raise

