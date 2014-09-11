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
import sys

from sipmessage import *

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

    LOGGER_NAME = 'bsip.stack'

    STATE_STOPPED = 0
    STATE_RUNNING = 1

    def __init__(self):
        self._state = self.STATE_STOPPED
        self._listeningPoints = {}
        self._logger = logging.getLogger(self.LOGGER_NAME)

    def start(self):
        """This method initiates the active processing of the stack."""

        self._state = SipStack.STATE_RUNNING

        # main loop
        self._logger.debug('entering main loop')
        while self._state == SipStack.STATE_RUNNING:
            sys.stdout.write('.')
            time.sleep(0.1)

        self._logger.debug('stopped')

    def stop(self):
        """This methods initiates the shutdown of the stack."""

        self._logger.debug('stopping')
        self._state = SipStack.STATE_STOPPED

    def getState(self):
        return self._state

    def isRunning(self):
        return self._state == SipStack.STATE_RUNNING

    def addListeningPoint(self, listeningPoint):
        key = listeningPoint.getKey()

        if not key in self._listeningPoints.keys():
            self._listeningPoints[key] = listeningPoint

    def sendRequest(self, request, transport = "udp"):
		"""Sends the Request statelessly, that is no transaction record is associated with
		 this action. This method implies that the application is functioning as a stateless proxy,
		 hence the underlying SipProvider acts statelessly. A stateless proxy simply forwards every
		 request it receives downstream and discards information about the Request message once
		 the message has been forwarded. A stateless proxy does not have any notion of a transaction.

		Once the Request message has been passed to this method, the SipProvider will forget about this
		Request. No transaction semantics will be associated with the Request and the SipProvider
		will not handle retranmissions for the Request. If these semantics are required it is the
		responsibility of the application not the SipProvider.
		"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('sendRequest() Enter')

		# get top via header 
		topVia = request.getTopmostViaHeader()

		# transport from top most via header has higher preference than parameter of this method call
		if not topVia is None:
			transport = topVia.getTransport()

		# find net element where to send request
		nextHop = self.getNextHop(request);
		if nextHop is None:
			raise ETransactionUnavailable('Cannot resolve next hop -- transaction unavailable')

		# modify transport protocol if necessary
		if transport == Sip.TRANSPORT_UDP and len(str(request)) > SipStack.MESSAGE_MAX_LENGTH:
			transport = Sip.TRANSPORT_TCP
			topVia.setTransport(transport)

		logger.debug('next hop identified, transport is %s, hop is %s', transport, str(nextHop))

		# look for listening point to be used for sending a message
		lp = self.getListeningPointForViaHeader(topVia)
		if lp is None:
			lp = self.getListeningPointForTransport(transport)
		if lp is None:
			lp = self.getListeningPointForTransport()
		if lp is None:
			raise ESipStackNoListeningPoint('No listening point available')

		self.fixViaHeaders(request, lp)

		# notify all interceptors
		for si in self._sipInterceptors:
			si.onMessageSend(request)

		message = str(request)

		localIpAddress = lp.getHop().getHost()
		localPort = lp.getHop().getPort()

		logger.debug('	local address: %s', localIpAddress)
		logger.debug('	local port: %d', localPort)
		logger.debug('	dst IP: %s', nextHop.getHost())
		logger.debug('	dst port: %d', nextHop.getPort())
		logger.debug('	msg length: %d', len(message))
		logger.debug('	transport: %s', transport)

		logger.debug('sending message:\n------\n%s\n-------', message)

		ipDispatcher = self.getIpDispatcher()
		ipDispatcher.sendSync(
			localIpAddress,
			0,
			nextHop.getHost(),
			nextHop.getPort(),
			message,
			transport)

		logger.debug('sendRequest() Leave')

