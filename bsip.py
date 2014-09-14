# sip client

# tip: http://pymotw.com/2/cmd/

import logging
import threading
import sipstack2
import sipmessage
import time
import cmd

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

class SipModulePrint(sipstack2.Module):
    """Print module"""

    def __init__(self):
        print "SipModulePrint initialized"
        # module name
        self.name = 'bsip-print-module' 
        # module priority
        self.priority = sipstack2.Module.PRIO_APPLICATION

    # Called on rx request
    def onRxRequest(self, rxData):
        print '-----------------------------'
        print 'Received SIP request'
        print '-----------------------------'
        print rxData.msg
        print '-----------------------------'
        return False

    # Called on rx response
    def onRxResponse(self, rxData):
        print '-----------------------------'
        print 'Received SIP response'
        print '-----------------------------'
        print rxData.msg
        print '-----------------------------'
        return False

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

        #localHop = sipmessage.Hop()
        #localHop.setHost('127.0.0.1')
        #localHop.setPort(5060)
        #lp = sipstack2.SipListeningPoint(self, localHop)

        self.stack = sipstack2.SipStack()
        self.stackThread = SipStackThread(self.stack)
        self.stackThread.start()

        self.tranUdp = sipstack2.TransportUdp(self.stack, '127.0.0.1', 5060)
        self.tranLoopback = sipstack2.TransportLoopback(self.stack)

        self.stack.registerModule(SipModulePrint())

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
        else:
            print 'unknown command'

    def do_register(self, userId):
        """Register user"""
        print "registering user %s" % userId 
             
if __name__ == '__main__':
    bsip = BSip()
    try:
        bsip.cmdloop()
    except:
    #except KeyboardInterrupt:
        bsip.stack.stop() 
        raise

