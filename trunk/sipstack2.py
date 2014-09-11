import logging
import sipmessage
import unittest
import socket
import select
import threading
import logging
import time
import hashlib
import copy

try:
    import queue
except ImportError:
    import Queue as queue

from sipmessage import *
#from accountmanager import *

#### exceptions ###########################################
class ESipStackException(Exception):
    pass

class ESipStackNotImplemented(ESipStackException):
    pass

class ESipStackInvalidArgument(ESipStackException):
    pass

class ESipStackNoListeningPoint(ESipStackException):
    pass

#### sip stack #######################################

class SipListeningPoint():
    """Sip Listening Point"""
    LOGGER_NAME = 'listening_point' 

    def __init__(self, sipStack, hop):

        self._sipStack = sipStack
        self._hop = hop
        self._buffer = "" 

        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('Creating socket %s' % self._hop)
        #ipDispatcher.createListeningSocket(self, self._hop.getHost(), self._hop.getPort(), self._hop.getTransport())

    def getHop(self):
        return self._hop

    def getKey(self):
        #result = 'lp_' + self._hop.getHost() + ':' + str(self._hop.getPort()) + '/' + self._hop.getTransport()
        result = 'lp_xxx'
        return result.lower()

    def onData(self, data, localHop, peerHop):
        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('onData() Enter, id: %s, buffer length: %d, data length: %d, local: %s, remote: %s'
            % (self.getKey(), len(self._buffer), len(data), localHop, peerHop))

        self._buffer += data
        # try to parse incoming data
        sipParser = sipmessage.SipParser()
        try:
            msg  = sipParser.parseSIPMessage(self._buffer)
            self._buffer = ""
        except ESipMessageException: 
            self._buffer += data 
            logger.debug('parsing failed, adding data to buffer, new buffer length is: %d' % len(self._buffer))
            if len(self._buffer) > 1024 * 10:
                logger.debug('exception when parsing message (data in buffer are too long)')
            return

        blockListeners = False

        event = None

        createTransactions = self._sipStack[SipStack.PARAM_CREATE_TRANSACTIONS]
        if createTransactions is None:
            createTransactions = True 
        logger.debug('value of parameter %s: %s', SipStack.PARAM_CREATE_TRANSACTIONS, str(createTransactions))

        createDialogs = self._sipStack[SipStack.PARAM_CREATE_DIALOGS]
        if createDialogs is None:
            createDialogs = True 
        logger.debug('value of parameter %s: %s', SipStack.PARAM_CREATE_DIALOGS, str(createDialogs))

        # prepare response event
        if isinstance(msg, sipmessage.SipRequest):

            # check for the required headers.
            topVia = msg.getTopmostViaHeader()
            msg.checkHeaders()

            # server transaction
            serverTransaction = self._sipStack.getServerTransactionForRequest(msg)

            # TODO: if serverTransaction not None then it is retransmission
            
            if createTransactions and serverTransaction is None:
                serverTransaction = self._sipStack.createServerTransaction(msg, self)

            #  modify transaction state according to state machine 
            if not serverTransaction is None:
                blockListeners = blockListeners or serverTransaction.processRequest(msg)

            # identify (match) dialog
            dialog = None

            # create new ResponseEvent
            event = SipRequestEvent(self, msg, serverTransaction, dialog)

        elif isinstance(msg, sipmessage.SipResponse):
            topVia = msg.getTopmostViaHeader()

            # identify (match) client transaction
            clientTransaction = self._sipStack.getClientTransactionForResponse(msg)

            #  modify transaction state according to state machine and response code
            if not clientTransaction is None:
                blockListeners = blockListeners or clientTransaction.processResponse(msg)

            # identify (match) dialog
            dialog = None

            # 100 - 199 or 200 - 299   
            if msg.getStatusCode() >= 100 and msg.getStatusCode() <= 299:
                dialogId = msg.getDialogId(True)
                if not dialogId is None:
                    dialog = self._sipStack.getDialogForResponse(msg)
                #cseqHeader = response.getHeaderByType(SipCSeqHeader);
                #if response.get TODO

            # create new ResponseEvent
            event = SipResponseEvent(self, msg, clientTransaction, dialog)

        blockListeners = self._sipStack.processMessageReceive(msg)

        # allow message preprocessing
        blockListeners = blockListeners or self._sipStack.preprocessSipEvent(event)

        # notify listeners
        if not blockListeners:
            for listener in self.getSipListeners():
                if isinstance(msg, sipmessage.SipRequest):
                    listener.processRequest(event)
                elif isinstance(msg, sipmessage.SipResponse):
                    listener.processResponse(event)
                else: 
                    listener.processIOException("x")

        logger.debug('onData() Leave')

    def getViaHeader(self):
        """Create Via header specific for this listening point instance"""

        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('getViaHeader() Enter')

        result = sipmessage.SipViaHeader()
        result.setHost(self.getHop().getHost())
        result.setTransport(self.getHop().getTransport())
        result.setPort(self.getHop().getPort())

        logger.debug('getViaHeader() Leave')

        return result

class SipStack():
    """This class represents the SIP protocol stack."""

    LOGGER_NAME = 'sip_stack'

    STATE_STOPPED = 0
    STATE_RUNNING = 1

    def __init__(self):
        self._state = self.STATE_STOPPED
        self._listeningPoints = {}

        # configure logging
        logging.basicConfig(level=logging.DEBUG, filename="sipstack", filemode="w")

    def start(self):
        """This method initiates the active processing of the stack."""

        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('start() Enter')

        self._state = SipStack.STATE_RUNNING

        logger.debug('start() Leave')

    def stop(self):
        """This methods initiates the shutdown of the stack."""

        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('stop() Enter')

        self._state = SipStack.STATE_STOPPED

        logger.debug('stop() Leave')

    def getState(self):
        return self._state

    def isRunning(self):
        return self._state == SipStack.STATE_RUNNING

    def addListeningPoint(self, listeningPoint):
        key = listeningPoint.getKey()

        if not key in self._listeningPoints.keys():
            self._listeningPoints[key] = listeningPoint

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):
    def testSetUp(self):
        self.localHop = Hop()
        self.localHop.setHost('127.0.0.1')
        self.localHop.setPort(5060)

        self.user1 = SipAddress()
        self.user1Uri = SipUri()
        self.user1Uri.setScheme(Uri.SCHEME_SIP)
        self.user1Uri.setUser("bob")
        self.user1Uri.setHost("beloxi.com")
        self.user1.setDisplayName('Bob')
        self.user1.setUri(self.user1Uri)

        self.user2 = SipAddress()
        self.user2Uri = SipUri()
        self.user2Uri.setScheme(Uri.SCHEME_SIP)
        self.user2Uri.setUser("alice")
        self.user2Uri.setHost("atlanta.com")
        self.user2.setDisplayName('Atlanta')
        self.user2.setUri(self.user2Uri)

    def testStackStartStop(self):
        s = SipStack()
        s.start()
        s.stop()

    def testStackAddListeningPoint(self):
        localHop = Hop()
        localHop.setHost('127.0.0.1')
        localHop.setPort(5060)

        s = SipStack()
        lp = SipListeningPoint(self, localHop)
        s.addListeningPoint(lp)

if __name__ == '__main__':
    unittest.main()

