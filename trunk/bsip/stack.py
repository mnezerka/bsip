
# http://c2.com/cgi/wiki?MessagingAsAlternativeToMultiThreading

import logging
import unittest
import socket
import select
import threading
import logging
import time
import hashlib
import copy
import sys
import random
import re

from sip import Sip
from sip import SipUtils
import message
from message import SipRequest
from message import SipResponse

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
    # transmitted data 
    data = None

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
    type = None 

    def __init__(self, stack):
        self.stack = stack

    def getId(self):
        return None

    def send(self, txData):
        pass

    def getViaHeader(self):
        return None

class TransportLoopback(Transport):
    """Loopback transport"""

    LOGGER_NAME = 'BSip.TransortLoopback' 
    type = 'loopback' 

    def __init__(self, stack):
        Transport.__init__(self, stack)
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.stack.transportManager.registerTransport(self)

    def getId(self):
        return 'loopback' 

class TransportUdp(Transport, IpSocketListener):
    """UDP Socket Transport"""

    LOGGER_NAME = 'BSip.TransortUdp' 
    type = Sip.TRANSPORT_UDP

    def __init__(self, stack, hop):
        assert isinstance(hop, message.Hop)
        Transport.__init__(self, stack)
        self.hop = hop 
        self.logger = logging.getLogger(self.LOGGER_NAME)

        self.logger.debug('Creating listening UDP socket for address: ' + str(self.hop))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.hop.getHost(), self.hop.getPort()))

        self.stack.transportManager.registerTransport(self)
        self.stack.ipDispatcher.registerListeningSocket(self.socket, self)

    def getId(self):
        return 'udp-%s-%d' % (self.hop.getHost(), self.hop.getPort()) 

    def onData(self, data, sourceAddress, destinationAddress):
        self.logger.debug('Received data of length %d from %s to %s' % (len(data), sourceAddress, destinationAddress))
        rxData = SipRxData()
        rxData.transport = self
        rxData.timestamp = time.time()
        rxData.source = sourceAddress 
        rxData.destination = destinationAddress 
        rxData.data = data

        self.stack.transportManager.onRxData(rxData)

    def send(self, txData):
        if txData.data is None:
            self.logger.error('Request to send data, but no binary data available')
            raise Exception('Request to send data, but no binary data available')

        self.logger.info('Sending data of size %d to %s' % (len(txData.data), str(txData.dest)))
        #self.logger.debug('Data dump:\n------\n%s\n-------', txData.data)

        sendSock = self.socket
        #sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #sendSock.bind((self.localAddress, 0))
        sendSock.sendto(txData.data, (txData.dest.getHost(), txData.dest.getPort()))
        #sendSock.close()

    def getViaHeader(self):
        topVia = message.SipViaHeader()
        topVia.setTransport(self.hop.getTransport())
        topVia.setHost(self.hop.getHost())
        topVia.setPort(self.hop.getPort())
        return topVia 

class TransportTcp(Transport, IpSocketListener):
    """TCP Socket Transport"""
    LOGGER_NAME = 'BSip.TransportTcp' 
    type = Sip.TRANSPORT_TCP

    def __init__(self, stack, localAddress, port):
        Transport.__init__(self, stack)
        self.localAddress = localAddress
        self.port = port
        self.logger = logging.getLogger(self.LOGGER_NAME)

        self.logger.debug('Creating listening TCP socket')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((localAddress, port))
        self.socket.listen(5)

        self.stack.transportManager.registerTransport(self)
        self.stack.ipDispatcher.registerListeningSocket(self.socket, self)

    def getId(self):
        return 'tcp-%s-%d' % (self.localAddress, self.port) 

    def onData(self, data, sourceAddress, destinationAddress):
        self.logger.debug('Received data')
        return
        self.logger.debug('Received data of length %d from %s to %s' % (len(data), sourceAddress, destinationAddress))
        rxData = SipRxData()
        rxData.transport = self
        rxData.timestamp = time.time()
        rxData.source = sourceAddress 
        rxData.destination = destinationAddress 
        rxData.data = data

        self.stack.transportManager.onRxData(rxData)

    def send(self, txData):
        if txData.data is None:
            self.logger.error('Request to send data, but no binary data available')
            raise Exception('Request to send data, but no binary data available')

        self.logger.info('Sending data of size %d to %s' % (len(txData.data), str(txData.dest)))
        #self.logger.debug('Data dump:\n------\n%s\n-------', txData.data)

        sendSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sendSock.bind((self.localAddress, 0))
        self.logger.debug('Establishing connectin to %s ...' % (str(txData.dest)))
        sendSock.connect(txData.dest)
        self.logger.debug('Connection established (%s)' % (str(txData.dest)))
        sendSock.send(txData.data)
        self.logger.debug('Data sent')
        sendSock.close()

    def getViaHeader(self):
        topVia = message.SipViaHeader()
        topVia.setTransport(Sip.TRANSPORT_UDP)
        topVia.setHost(self.localAddress)
        topVia.setPort(self.port)
        return topVia 

class Module():
    """Sip module base class"""

    PRIO_TRANSPORT_LAYER = 8
    PRIO_TRANSACTION_LAYER = 16
    PRIO_UA_PROXY_LAYER =32 
    PRIO_DIALOG_USAGE = 48 
    PRIO_APPLICATION = 64 

    def __init__(self):
        self.stack = None 

        # module priority
        self.priority = Module.PRIO_TRANSPORT_LAYER

    def getId(self):
        """Get module id"""
        return 'module'

    # Called to load the module
    def onLoad(self, stack):
        self.stack = stack

    # Called before unload
    def onUnload(self):
        pass

    # Called on rx request
    def onRxRequest(self, rxData):
        pass

    # Called on rx response
    def onRxResponse(self, rxData):
        pass

    # Called on tx request
    def onTxRequest(self, txData):
        pass

    # Called on tx response
    def onTxResponse(self, txData):
        pass

    # Called on transaction state changed
    def onTranState(self, tran):
        pass

class ModuleSipLog(Module):
    """Sip module for logging all incoming and outgoing sip messages"""

    LOGGER_NAME = 'BSip.SipLog' 

    def __init__(self):
        Module.__init__(self)
        self.priority = Module.PRIO_TRANSPORT_LAYER
        self.logger = logging.getLogger(self.LOGGER_NAME)

    def getId(self):
        return 'siplog'

    def onRxRequest(self, rxData):
        self.logger.info('-----------------------------')
        self.logger.info('Received SIP request')
        self.logger.info('-----------------------------')
        self.logger.info(rxData.msg)
        self.logger.info('-----------------------------')
        return False

    def onRxResponse(self, rxData):
        self.logger.info('-----------------------------')
        self.logger.info('Received SIP response')
        self.logger.info('-----------------------------')
        self.logger.info(rxData.msg)
        self.logger.info('-----------------------------')
        return False

    def onTxRequest(self, txData):
        self.logger.info('-----------------------------')
        self.logger.info('Sent SIP request')
        self.logger.info('-----------------------------')
        self.logger.info(txData.msg)
        self.logger.info('-----------------------------')
        return False

    def onTxResponse(self, txData):
        self.logger.info('-----------------------------')
        self.logger.info('Sent SIP response')
        self.logger.info('-----------------------------')
        self.logger.info(txData.msg)
        self.logger.info('-----------------------------')
        return False

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

        sipParser = message.SipParser()
        try:
            rxData.msg  = sipParser.parseSIPMessage(rxData.data)
        except ESipMessageException: 
            #logger.debug('parsing failed, adding data to buffer, new buffer length is: %d' % len(self._buffer))
            logger.debug('parsing failed, adding data to buffer, new buffer length is ...')

        self.stack.onRxMessage(rxData)

    def send(self, txData):
        # check if transport is registered
        pass

    def acquiureTransport(self, transportType):
        transport = None
        for tId in self.transports:
            if transportType is None or self.transports[tId].type == transportType:
                transport = self.transports[tId]
                break
        return transport

class SipStack():
    """This class represents the SIP protocol stack."""

    LOGGER_NAME = 'BSip.Stack'

    def __init__(self):
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.modules = []
        self.transportManager = TransportManager(self)
        self.ipDispatcher = IpDispatcher(self)
        self.transactions = {}

    def loop(self):
        """Main loop"""
        self.logger.debug('Entering main loop')

        # allow ip dispatcher to do io operations on all sockets
        self.ipDispatcher.doSelect()

        # TODO - process all items in stack queue

    def registerModule(self, module):
        self.logger.debug('Registering module %s (priority %d)' % (module.getId(), module.priority))
        self.modules.append(module)
        module.onLoad(self)

    def getModule(self, moduleId):
        result = None
        for m in self.modules:
            if m.getId() == moduleId:
                result = m
                break             
        return result

    def onRxMessage(self, rxData):
        self.logger.debug('Received SIP message')

        # distribute message to modules according to priorities
        msg = rxData.msg
        consumed = False
        # 1st loop is over all priorities
        for priority in [Module.PRIO_TRANSPORT_LAYER, Module.PRIO_TRANSACTION_LAYER, Module.PRIO_UA_PROXY_LAYER, Module.PRIO_DIALOG_USAGE, Module.PRIO_APPLICATION]:
            # 2nd loop is over all modules 
            for m in self.modules:
                if m.priority == priority:
                    if isinstance(msg, SipRequest):
                       consumed = m.onRxRequest(rxData)
                    elif isinstance(msg, SipResponse):
                       consumed = m.onRxResponse(rxData)
                    else:
                        raise BSipException('Unknown SIP message type') 

                    if consumed: 
                        self.logger.debug('Message consumed by module: %s' % m.getId())
                        break

            # exit 1s loop
            if consumed: 
                break 

        if not consumed:
            self.logger.warning('Message not consumed by any of modules')

    def sendStateless(self, txData):
        if txData.transport is None:
            raise Exception('no transport selected')

                # serialize SIP message
        txData.data = str(txData.msg)

        # distribute message to modules with transport priority 
        # loop is over all modules 
        consumed = False
        for m in self.modules:
            if m.priority != Module.PRIO_TRANSPORT_LAYER:
                continue
            if isinstance(txData.msg, SipRequest):
               consumed = m.onTxRequest(txData)
            elif isinstance(txData.msg, SipResponse):
               consumed = m.onTxResponse(txData)
            else:
                raise BSipException('Unknown SIP message type') 

            if consumed: 
                self.logger.debug('Message consumed by module: %s' % m.getId())
                break

        if not consumed:
            txData.transport.send(txData)

    def fixRequestForTransport(self, request, transport):
        assert isinstance(request, SipRequest)
        assert isinstance(transport, Transport)

        # get message top via header
        topVia = request.getTopViaHeader()
        if topVia is None: 
            self.logger.debug('Adding new Via header generated by transport')
            # get transport header
            transportVia = transport.getViaHeader()
            request.addHeader(transportVia)
        else:
            if transport.type != topVia.getTransport():
                topVia.setTransport(transport.type)
            if transport.hop.getHost() != topVia.getHost():
                topVia.setHost(transport.hop.getHost())
            if transport.hop.getPort() != topVia.getPort():
                topVia.setPort(transport.hop.getPort())

        # get message contact header
        contactHeader = request.getHeaderByType(message.ContactHeader)
        if contactHeader is None:
            contactHeader = message.ContactHeader()
            request.addHeader(contactHeader);

        contactUri = message.SipUri()
        contactUri.setScheme(message.Uri.SCHEME_SIP)
        contactUri.setHost(transport.hop.getHost())
        contactUri.setPort(transport.hop.getPort())
        contactAddress = message.SipAddress()
        contactAddress.setUri(contactUri)
        contactHeader.setAddress(contactAddress)

    def acquireTransport(self, transportType = None):
        return self.transportManager.acquiureTransport(transportType)

######## stack ####################

class UnitTestCase(unittest.TestCase):
    def testX(self):
        pass

def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


