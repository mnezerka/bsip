
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

class ESipMessageException(Exception):
    pass

class ESipMessageNotImplemented(ESipMessageException):
    pass

class ESipMessageHeaderInvalid(ESipMessageException):
    pass

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

    def send(self, txData):
        if txData.data is None:
            self.logger.error('Request to send data, but no binary data available')
            raise Exception('Request to send data, but no binary data available')

        self.logger.info('Sending data of size %d to %s' % (len(txData.data), str(txData.dest)))
        #self.logger.debug('Data dump:\n------\n%s\n-------', txData.data)

        sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sendSock.bind((self.localAddress, 0))
        sendSock.sendto(txData.data, txData.dest)
        sendSock.close()

    def getViaHeader(self):
        topVia = SipViaHeader()
        topVia.setTransport(Sip.TRANSPORT_UDP)
        topVia.setHost(self.localAddress)
        topVia.setPort(self.port)
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
        topVia = SipViaHeader()
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
    def onTsxState(tsx):
        pass

    def onRegistered(self, stack):
        self.stack = stack

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

        sipParser = SipParser()
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
            if self.transports[tId].type == transportType:
                transport = self.transports[tId]
                break
        return transport

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
        self.logger.debug('Registering module %s (priority %d)' % (module.getId(), module.priority))
        self.modules.append(module)
        module.onRegistered(self)

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

        # fix message according to transport
        self.fixTxData(txData)
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

    def fixTxData(self, txData):
        if txData.transport is None:
            return

        # get message top via header
        topVia = txData.msg.getTopViaHeader()
        if topVia is None: 
            self.logger.debug('Adding new Via header generated by listening point')
            # get transport header
            transportVia = txData.transport.getViaHeader()
            txData.msg.addHeader(transportVia)
            print "This is via header", str(transportVia)
        else:
            if txData.transport.type != topVia.getTransport():
                topVia.setTransport(txData.transport.type)
            if txData.transport.localAddress != topVia.getHost():
                topVia.setHost(txData.transport.localAddress)
            if txData.transport.port != topVia.getPort():
                topVia.setPort(txData.transport.port)

        # get message contact header
        contactHeader = txData.msg.getHeaderByType(ContactHeader)
        if contactHeader is None:
            contactHeader = ContactHeader()

        contactUri = SipUri()
        contactUri.setScheme(Uri.SCHEME_SIP)
        contactUri.setHost(txData.transport.localAddress);
        contactUri.setPort(txData.transport.port);
        contactHeader.setAddress(contactUri)
        txData.msg.addHeader(contactHeader);

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

    def acquireTransport(self, transportType):
        return self.transportManager.acquiureTransport(transportType)

######## stack ####################

class UnitTestCase(unittest.TestCase):
    def setUp(self):
        self.CONTENT = 'MyContent'
        self.USR_BOB_USERNAME =  'bob'
        self.USR_BOB_DISPLAYNAME =  'Bob'
        self.USR_BOB_DOMAIN =  'beloxi.com'
        self.USR_BOB_SHORT = 'sip:%s@%s' % (self.USR_BOB_USERNAME, self.USR_BOB_DOMAIN)
        self.USR_BOB_ADDR = '"%s" <%s>' % (self.USR_BOB_DISPLAYNAME, self.USR_BOB_SHORT)

        self.localHop = Hop()
        self.localHop.setHost('127.0.0.1')
        self.localHop.setPort(5060)

        self.user1 = SipAddress()
        self.user1Uri = SipUri()
        self.user1Uri.setScheme(Uri.SCHEME_SIP)
        self.user1Uri.setUser("ITSY000001")
        self.user1Uri.setHost("brn10.iit.ims")
        self.user1.setDisplayName('ITSY000001')
        self.user1.setUri(self.user1Uri)

        self.user2 = SipAddress()
        self.user2Uri = SipUri()
        self.user2Uri.setScheme(Uri.SCHEME_SIP)
        self.user2Uri.setUser("ITSY000002")
        self.user2Uri.setHost("brn10.iit.ims")
        self.user2.setDisplayName('ITSY000002')
        self.user2.setUri(self.user2Uri)

    def testHop(self):
        IP = "1.1.1.1"
        h = Hop()
        h = Hop("1.1.1.1")
        self.assertEqual(h.getHost(), IP)
        h = Hop("1.1.1.1:89")
        self.assertEqual(h.getHost(), IP)
        self.assertEqual(h.getPort(), 89)
        h = Hop(("1.1.1.1", 89))
        self.assertEqual(h.getHost(), IP)
        self.assertEqual(h.getPort(), 89)
        h.setTransport("udp")
        self.assertEqual(h.getTransport(), "udp")

    def testSipUri(self):
        x = SipUri()
        x.setScheme(Sip.URI_PREFIX_SIP)
        x.setHost(self.USR_BOB_DOMAIN)
        x.setUser(self.USR_BOB_USERNAME)
        self.assertEqual(self.USR_BOB_SHORT, str(x))

        x = SipUri(self.USR_BOB_SHORT)
        self.assertEqual(self.USR_BOB_SHORT, str(x))

        addr = self.USR_BOB_SHORT + ';transport=tcp'
        x = SipUri(addr)
        self.assertEqual(addr, str(x))

    def testSipAddress(self):
        x = SipAddress()
        x.setDisplayName(self.USR_BOB_DISPLAYNAME)
        u = SipUri(self.USR_BOB_SHORT)
        x.setUri(u)
        self.assertEqual(str(x), self.USR_BOB_ADDR)

        x = SipAddress(self.USR_BOB_SHORT)
        self.assertEqual(str(x), self.USR_BOB_SHORT)

        x = SipAddress(self.USR_BOB_ADDR)
        self.assertEqual(str(x), self.USR_BOB_ADDR)

    def testSipMessage(self):
        m = SipMessage()
        m.setContent(self.CONTENT)

        m = SipMessage()
        fh = SipFromHeader('sip:alice@blue.com')
        m.addHeader(fh)
        th = SipToHeader('sip:bob@blue.com')
        m.addHeader(th)
        cih = SipCallIdHeader('callid')
        m.addHeader(cih)
        cseq = SipCSeqHeader('34 REGISTER')
        m.addHeader(cseq)
        m.setContent(self.CONTENT)
        m.getTransactionId()

        tv = SipViaHeader('SIP/2.0/UDP some.host;branch=z9hG4bKsomebranch')
        m.addHeader(tv)
        m.getTransactionId()

    def testMediaType(self):
        MT = "application/sdp"
        mt = MediaType(MT)
        self.assertEqual(str(mt), MT)

    def testAddressHeader(self):
        header = 'From: ' + self.USR_BOB_ADDR

        h = SipAddressHeader('From')
        a = SipAddress(self.USR_BOB_ADDR)
        h.setAddress(a)
        self.assertEqual(str(h), header)

        h = SipAddressHeader('From', self.USR_BOB_ADDR)
        self.assertEqual(str(h), header)

    def testAuthenticationInfoHeader(self):
        h = AuthenticationInfoHeader()
        h.setNextNonce('xnoncex')
        self.assertEqual(h.getNextNonce(), 'xnoncex')
        str(h)
        h = AuthenticationInfoHeader('nextnonce="xxx"')
        self.assertEqual(h.getNextNonce(), 'xxx')
        str(h)

    def testAuthenticationHeader(self):
        h = AuthenticationHeader('test')
        h.setScheme('Digest')
        h.setNonce('xnoncex')
        h.setCNonce('xcnoncex')
        h.setNC(45)
        str(h)

        h = AuthenticationHeader('test', 'Digest algorithm="md5", nonce="xxx"')
        str(h)

    def testAuthorizationHeader(self):
        h = AuthorizationHeader()
        h.setScheme('Digest')
        h.setNC(34)
        str(h)

    def testContentLengthHeader(self):
        h = ContentLengthHeader("34")
        self.assertEqual(h.getContentLength(), 34)
        h.setContentLength(45)
        self.assertEqual(h.getContentLength(), 45)
    
    def testContentTypeHeader(self):
        h = ContentTypeHeader("application/sdp")
        str(h)

    def testViaHeader(self):
        h = SipViaHeader()
        h.setHost('127.0.0.1')
        h.setProtocol('udp')
        h.setPort(5060)

        h2 = SipViaHeader('SIP/2.0/UDP some.host;branch=z9hG4bKsomebranch;lskpmc=P01')

    def testWwwAuthenticateHeader(self):
        h = WwwAuthenticateHeader()
        h.setScheme('Digest')
        h.setAlgorithm('md5')
        h.setDomain('some.domain')
        h.setNonce('ncval')
        h.setOpaque('opqval')
        h.setQop('qopval')
        h.setRealm('some.realm')
        h.setUri('some.uri')
        h.setStale(False)
        str(h)

    def testSipUtils(self):
        SipUtils.generateCallIdentifier('xyz')
        SipUtils.generateTag()
        SipUtils.generateBranchId()

    def testMessageFactory(self):
        inv = MessageFactory.createRequestInvite(self.user1, self.user2, self.localHop)
        ack = MessageFactory.createRequestAck(inv)

    def testHeaderFactory(self):
        rrh = SipRecordRouteHeader();
        rrh.setAddress(self.user1)
        rrh["x"] = "val1"
        rrh["y"] = "val2"
        rh = HeaderFactory.createRouteFromRecordRoute(rrh)
        self.assertEqual(rrh.getAddress().getDisplayName(), rh.getAddress().getDisplayName())
        self.assertEqual(rrh["x"], rh["x"])
        self.assertEqual(rrh["y"], rh["y"])

    def testSipMessageDialogId(self):
        msg = MessageFactory.createRequestInvite(self.user1, self.user2, self.localHop)
        self.assertEqual(msg.getDialogId(True), None)
        hFrom = msg.getFromHeader()
        hTo = msg.getToHeader()
        hFrom.setTag("fromtag")
        hTo.setTag("totag")
        callId = msg.getCallId()
        self.assertEqual(msg.getDialogId(False), callId + ":fromtag:totag")
        self.assertEqual(msg.getDialogId(True), callId + ":totag:fromtag")

    def testSipMessageParserMultipleHeaderValues(self):
        sipParser = SipParser()
        headers = sipParser.parseHeader("Contact: \"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>;q=0.7; expires=3600, \"Mr. Wa\,t\:s\=on\" <sip:watson@bell-telephone.com> ;q=0.1")
        self.assertEqual(len(headers), 2)
        self.assertEqual(headers[0].getAddress().getDisplayName(), "Mr. Watson")
        self.assertEqual(headers[0].getAddress().getUri().getUser(), "watson")
        self.assertEqual(headers[0].getAddress().getUri().getHost(), "worcester.bell-telephone.com")
        self.assertEqual(headers[1].getAddress().getDisplayName(), "Mr. Wa\,t\:s\=on")
        self.assertEqual(headers[1].getAddress().getUri().getUser(), "watson")
        self.assertEqual(headers[1].getAddress().getUri().getHost(), "bell-telephone.com")

    def testSipMessageParserOptions(self):
        f = open('data/sip_options.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

    def testSipMessageParserInvite(self):
        f = open('data/sip_invite.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

    def testSipMessageParser403Forbidden(self):
        f = open('data/sip_register_403_forbidden.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


