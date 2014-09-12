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

class BSip(cmd.Cmd):
    """BSip command line processor"""

    def __init__(self):
        cmd.Cmd.__init__(self)
        # initialize logging
        self.logger = logging.getLogger('bsip')
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

        self.stack = sipstack2.SipStack()
        self.stackThread = SipStackThread(self.stack)
        self.stackThread.start()
        #time.sleep(1)
        #st.stop()
        #lp = SipListeningPoint(self, localHop)
        #s.addListeningPoint(lp)

    def do_greet(self, line):
        print "hello"

    def do_exit(self, line):
        self.stackThread.stop()
        """Quit BSip application"""
        return True
             
def main():

    # initialize logging
    logger = logging.getLogger('bsip')
    logger.setLevel(logging.DEBUG)
    h = logging.FileHandler(filename='bsip.log', mode='w')
    h.setLevel(logging.DEBUG)
    f = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%d/%m/%Y %H:%M:%S')
    h.setFormatter(f)
    logger.addHandler(h)
    logger.debug('Logging initialized')

    localHop = sipmessage.Hop()
    localHop.setHost('127.0.0.1')
    localHop.setPort(5060)

    s = sipstack2.SipStack()
    st = SipStackThread(s)
    st.start()
    time.sleep(1)
    st.stop()
    #lp = SipListeningPoint(self, localHop)
    #s.addListeningPoint(lp)


if __name__ == '__main__':

    BSip().cmdloop()
    #main()

