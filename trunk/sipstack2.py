
# http://c2.com/cgi/wiki?MessagingAsAlternativeToMultiThreading

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

class ESipStackException(Exception):
    """Base class for all BSip exceptions"""
    pass

class SipRxData():
    """Received data"""

    # the transport that received the msg.
    transport = None
    # packet arrival time
    timestamp = None
    # source address
    source = None
    # received message
    msg = None
    # received message
    data = None

class SipTxData():
    """Transmitted data"""

    # transport being used
    transport = None
    # destination address
    dest = None
    # transmitted message
    msg = None

class IpSocketListener():
    """Base abstract class for all listeners to socket events""" 

    def onData(self, data, sourceAddress, destinationAddress):
        pass

    def onClientSocket(self, socket):
        pass

class IpDispatcher():
    """Class responsible for IP network operations"""
 
    LOGGER_NAME = 'BSip.IpDispatcher'

    def __init__(self, stack):
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.stack = stack
        self.sockets = [] 
        self.socketsListening = [] 
        self.socketsClient = [] 

     # add transport sockets to global list of observed sockets
    def registerListeningSocket(self, socket, transport):
        """Register socket for IO operations in main loop"""
        self.logger.debug('Registering socket %s for transport %s' % (socket, transport.getId()))
        self.sockets.append([socket, transport])
        self.socketsListening.append(socket)

    def getTransportForSocket(self, fd):
        """Get transport instance associated with socket"""

        result = None
        for socketData in self.sockets:
            if socketData[0] == fd:
                result = socketData[1]
                break
        return result 

    def doSelect(self):
        """Run select on registered sockets"""

        socketsInput = self.socketsClient + self.socketsListening

        if len(socketsInput) == 0:
            return
        
        self.logger.debug('select iteration for %d sockets', len(socketsInput))

        try:
            (in_, out_, exc_) = select.select(socketsInput, [] , [], 1)
        except:
            self.logger.error('IO error (select failed)')
            raise
            #raise EBSipException('IO error (select failed)')

        for fd in in_:

            transport = self.getTransportForSocket(fd)

            # event on listening sockets
            if fd in self.socketsListening:
                localAddr = fd.getsockname()
                # event on UDP socket
                if fd.type == socket.SOCK_DGRAM:
                    (data, peerAddr) = fd.recvfrom(1024 * 8)
                    self.logger.debug('Finished reading from UDP socket: %d bytes', len(data))
                    transport.onData(data, localAddr, peerAddr)
                # event on TCP socket
                elif fd.type == socket.SOCK_STREAM:
                    clientSocket, address = fd.accept()
                    self.logger.debug('Incoming tcp connection %d from %s', clientSocket.fileno(), address)
                    #self.__clientSockets.append(clientSocket)
                    #self.__ipDispatcher.registerClientSocket(fd, clientSocket)
                # event on client sockets (tcp connection local sockets)
            else:
                self.logger.debug('Reading data from %d', fd.fileno())
                (data, peerAddr) = fd.recvfrom(1024 * 8)
                #peerHop = Hop(peerAddr, Sip.TRANSPORT_UDP)
                if data:
                    while True:
                        dataChunk = fd.recv(1024 * 8)
                        if not dataChunk: break
                        data += dataChunk

                    self.logger.debug('Finished reading from TCP socket: %d bytes', len(data))
                    #event = WorkerEventData(data, processor, localHop, peerHop)
                    #self.__queue.put(event)
                else:
                    self.logger.debug('Connection to %d closed', fd.fileno())
                    fd.close()

                    #if fd in self.__clientSockets:
                    #    self.__clientSockets.remove(fd)
                    #else:
                    #    self.__ipDispatcher.removeListeningSocket(fd)

            for fd in out_:
                pass
            
            for fd in exc_:
                pass

class Transport:
    """Base class for all transports"""

    LOGGER_NAME = 'BSip.Transport' 

    def __init__(self, stack):
        self.stack = stack

    def getId(self):
        return None

    def sendMsg(self, msg):
        pass

class TransportLoopback(Transport):
    """Loopback transport"""

    LOGGER_NAME = 'BSip.TransortLoopback' 

    def __init__(self, stack):
        Transport.__init__(self, stack)
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.stack.transportManager.registerTransport(self)

    def getId(self):
        return 'loopback' 

class TransportUdp(Transport, IpSocketListener):
    """UDP Socket Transport"""

    LOGGER_NAME = 'BSip.TransortUdp' 

    def __init__(self, stack, localAddress, port):
        Transport.__init__(self, stack)
        self.localAddress = localAddress
        self.port = port
        self.logger = logging.getLogger(self.LOGGER_NAME)

        self.logger.debug('Creating listening UDP socket')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((localAddress, port))

        self.stack.transportManager.registerTransport(self)
        self.stack.ipDispatcher.registerListeningSocket(self.socket, self)

    def getId(self):
        return 'udp-%s-%d' % (self.localAddress, self.port) 

    def onData(self, data, sourceAddress, destinationAddress):
        self.logger.debug('Received data of length %d from %s to %s' % (len(data), sourceAddress, destinationAddress))
        rxData = SipRxData()
        rxData.transport = self
        rxData.timestamp = time.time()
        rxData.source = sourceAddress 
        rxData.destination = destinationAddress 
        rxData.data = data

        self.stack.transportManager.onRxData(rxData)

class TransportTcp(Transport, IpSocketListener):
    """TCP Socket Transport"""
    LOGGER_NAME = 'BSip.TransportTcp' 

    def __init__(self, stack, localAddress, port):
        SipTransport.__init__(self, stack)
        self.localAddress = localAddress
        self.port = port
        self.logger = logging.getLogger(self.LOGGER_NAME)

        self.logger.debug('Creating listening TCP socket')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((localAddress, port))

        self.stack.registerTransport(self)
        self.stack.getIpDispatcher().registerListeningSocket(self.socket, self)

    def getId(self):
        return 'tcp-%s-%d' % (self.localAddress, self.port) 

class Module():
    """Sip module base class"""

    PRIO_TRANSPORT_LAYER = 8
    PRIO_TRANSACTION_LAYER = 16
    PRIO_UA_PROXY_LAYER =32 
    PRIO_DIALOG_USAGE = 48 
    PRIO_APPLICATION = 64 

    def __init__(self):
        # module name
        self.name = 'module' 
        # module priority
        self.priority = PRIO_TRANSPORT_LAYER

    # Called to load the module
    def onLoad(self, stack):
        pass

    # Called to start
    def start(self, stack):
        pass

    # Called to stop
    def stop(self):
        pass

    # Called before unload
    def unload(self):
        pass

    # Called on rx request
    def onRxRequest(rxData):
        pass

    # Called on rx response
    def onRxResponse(rxData):
        pass

    # Called on tx request
    def onTxRequest(rxData):
        pass

    # Called on tx response
    def onTxResponse(rxData):
        pass

    # Called on transaction state changed
    def onTsxState(tsx):
        pass

class TransportManager():
    """Responsible for management of all transports"""

    LOGGER_NAME = 'BSip.TransportManager'

    def __init__(self, stack):
        self.stack = stack
        self.transports = {}
        self.buffers = {}
        self.logger = logging.getLogger(self.LOGGER_NAME)

    def registerTransport(self, transport):
        """Create transport instance"""
        self.logger.debug('Registering transport %s' % transport.getId())
        if not transport.getId() in self.transports: 
            self.transports[transport.getId()] = transport

    def onRxData(self, rxData):
        self.logger.debug('Sip data of length %d received from transport %s' % (len(rxData.data), rxData.transport.getId()))

        sipParser = sipmessage.SipParser()
        try:
            rxData.msg  = sipParser.parseSIPMessage(rxData.data)
        except ESipMessageException: 
            #logger.debug('parsing failed, adding data to buffer, new buffer length is: %d' % len(self._buffer))
            logger.debug('parsing failed, adding data to buffer, new buffer length is ...')

        self.stack.onRxMessage(rxData)
        
class SipStack():
    """This class represents the SIP protocol stack."""

    LOGGER_NAME = 'BSip.Stack'

    STATE_STOPPED = 0
    STATE_RUNNING = 1

    def __init__(self):
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.state = self.STATE_STOPPED
        self.modules = []
        self.transportManager = TransportManager(self)
        self.ipDispatcher = IpDispatcher(self)

    def start(self):
        """This method initiates the active processing of the stack."""

        self.state = SipStack.STATE_RUNNING

        # main loop
        self.logger.debug('entering main loop')
        while self.state == SipStack.STATE_RUNNING:

            # allow ip dispatcher to do io operations on all sockets
            self.ipDispatcher.doSelect()

            # process events
            # while not empty self.eventQueue
            #   processEvent()
             
            #sys.stdout.write('.')
            time.sleep(0.1)

        self.logger.debug('stopped')

    def stop(self):
        """This methods initiates the shutdown of the stack."""
        self.logger.debug('stopping')
        self.state = SipStack.STATE_STOPPED

    def getState(self):
        return self.state

    def isRunning(self):
        return self.state == SipStack.STATE_RUNNING

    def registerModule(self, module):
        self.logger.debug('Registering module %s (priority %d)' % (module.name, module.priority))
        self.modules.append(module)

    def onRxMessage(self, rxData):
        self.logger.debug('Received SIP message')

        # distribute message to modules according to priorities
        msg = rxData.msg
        consumed = False
        for priority in [Module.PRIO_TRANSPORT_LAYER, Module.PRIO_TRANSACTION_LAYER, Module.PRIO_UA_PROXY_LAYER, Module.PRIO_DIALOG_USAGE, Module.PRIO_APPLICATION]:
            for m in self.modules:
                if m.priority == priority:
                    if isinstance(msg, sipmessage.SipRequest):
                       consumed = m.onRxRequest(rxData)
                    elif isinstance(msg, sipmessage.SipResponse):
                       consumed = m.onRxResponse(rxData)
                    else:
                        raise BSipException('Unknown SIP message type') 
                    if consumed: 
                        self.logger.debug('Message consumed by module: %s' % m.getId())
                        break
                if consumed: 
                    break
        if not consumed:
            self.logger.warning('Message not consumed by any of modules')

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

        logger.debug('  local address: %s', localIpAddress)
        logger.debug('  local port: %d', localPort)
        logger.debug('  dst IP: %s', nextHop.getHost())
        logger.debug('  dst port: %d', nextHop.getPort())
        logger.debug('  msg length: %d', len(message))
        logger.debug('  transport: %s', transport)

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


