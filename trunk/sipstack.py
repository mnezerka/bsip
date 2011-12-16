
import logging
import sipmessage
import unittest
import Queue
import socket
import select
import threading
import logging
import time
import hashlib

from sipmessage import *
#from accountmanager import *

class ESipStackException(Exception):
	pass

class ESipStackNotImplemented(ESipStackException):
	pass

class ESipStackInvalidArgument(ESipStackException):
	pass

class ESipStackNoListeningPoint(ESipStackException):
	pass

class SipRequestEvent(object):
	"""This class represents an Request event that is passed from a SipStack to its SipListener(s).
	
	This specification handles the passing of request messages to the application use the event model.
	An application (SipListener) will register with the SIP protocol stack and listen for
	Request events.

	RequestEvent contains the following elements:

	 * source - the source of the event i.e. the SipStack sending the RequestEvent
	 * serverTransaction - the server transaction this RequestEvent is associated with.
	 * Request - the Request message received 
	"""

	def __init__(self, source, request, serverTransaction = None, dialog = None):
		"""Constructs a RequestEvent encapsulating the Request that has been received by
		the underlying SipProvider. This RequestEvent once created is passed to processRequest
		method of the SipListener for application processing."""

		# the source of the event i.e. the SipProvider sending the ResponseEvent.
		self._source = source

		# the server transaction this ResponseEvent is associated with.
		self._serverTransaction = serverTransaction

		# the Request message received on the SipProvider that needs passed
		# to the application
		self._request = request

		self._dialog = dialog 

	def getServerTransaction(self):
		"""Gets the server transaction associated with this RequestEvent"""
		return self._serverTransaction

	def getDialog(self):
		"""Gets the dialog with which this Event is associated.
		
		This method separates transaction support from dialog support. This enables application
		developers to access the dialog associated to this event without having to query the transaction
		associated to the event. 
		"""
		return self._dialog

	def getRequest(self):
		"""Gets the Request message encapsulated in this ResponseEvent."""
		return self._request

	def getSource(self):
		return self._source

	def getRemoteIpAddress(self):
		return None	

	def setRemoteIpAddress(self, remoteIpAddress):
		pass

	def getRemotePort(self):
		return None

	def setRemotePort(self, remotePort):
		pass

class SipResponseEvent(object):

	def __init__(self, source, response, clientTransaction = None, dialog = None):
		# the source of the event i.e. the SipProvider sending the ResponseEvent.
		self._source = source

		# the client transaction this ResponseEvent is associated with.
		self._clientTransaction = clientTransaction

		# the Response message received on the SipProvider that needs passed
		# to the application encapsulated in a ResponseEvent. 
		self._response = response 

		self._dialog = dialog 

	def getClientTransaction(self):
		"""Gets the client transaction associated with this ResponseEvent"""
		return self._clientTransaction

	def getDialog(self):
		"""Gets the Dialog associated with the event or null if no dialog exists.

		This method separates transaction support from dialog support. This enables
		application developers to access the dialog associated to this event without
		having to query the transaction associated to the event. For example the transaction
		associated with the event may return None because the final response for the
		transaction has already been received and the stack has no more record of the
		transaction. This situation can occur when a UAC sends requests out through
		a forking proxy. Responses that all refer to the same transaction may be sent
		by the targets of the fork but each response may be stamped with a different
		To tag, thus referring to different Dialogs on the UAC. The first final response
		terminates the transaction but the UAC may want to create a Dialog on a subsequent
		response.
		"""
		return self._dialog

	def getResponse(self):
		"""Gets the Response message encapsulated in this ResponseEvent."""
		return self._response

	def getSource(self):
		return self._source


class SipListener(object):
	"""This interface represents the application view to a SIP stack
	therefore defines the application's communication channel to the
	SIP stack. This interface defines the methods required by an applications
	to receive and process Events that are emitted by an object implementing
	the SipProviderinterface."""

	def processDialogTerminated(self, dialogTerminatedEvent):
		"""Process an asynchronously reported DialogTerminatedEvent."""
		raise EInterfaceCall()

	def processIOException(self, exceptionEvent):
		"""Process an asynchronously reported IO Exception."""
		raise EInterfaceCall()

	def processRequest(self, requestEvent):
		"""Processes a Request received on a SipProvider upon which this SipListener is registered."""
		raise EInterfaceCall()

	def processResponse(self, responseEvent):
		"""Processes a Response received on a SipProvider upon which this SipListener is registered."""
		raise EInterfaceCall()

	def processTimeout(self, timeoutEvent):
		"""Processes a retransmit or expiration Timeout of an underlying Transactionhandled by this SipListener."""
		raise EInterfaceCall()

	def processTransactionTerminated(self, transactionTerminatedEvent):
		"""Process an asynchronously reported TransactionTerminatedEvent."""
		raise EInterfaceCall()




class IpProcessor(object):
	"""Abstract class for all Ip processors"""

	# process incoming data
	def onData(self, data):
		raise EInterfaceCall()

class SipListeningPoint(IpProcessor):
	"""Sip Listening Point"""
	LOGGER_NAME = 'listening_point'	

	def __init__(self, sipStack, ipAddress, port, transport):

		IpProcessor.__init__(self)

		self._sipStack = sipStack
		self._ipAddress = ipAddress 
		self._port = port 
		self._transport = transport

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('Creating socket (%s, %d, %s)', self._ipAddress, self._port, self._transport)
		ipDispatcher = self._sipStack.getIpDispatcher()
		ipDispatcher.createListeningSocket(self, self._ipAddress, self._port, self._transport)


	def getPort(self):
		return self._port 

	def getTransport(self):
		return self._transport

	def setIpAddress(self, ipAddress):
		self._ipAddress = ipAddress

	def getIpAddress(self):
		return self._ipAddress

	def getKey(self):
		result = 'lp_' + self._ipAddress + ':' + str(self._port) + '/' + self._transport 
		return result.lower()
    
	def onData(self, data):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('onData() Enter data length: %d', len(data))

		# try to parse incoming data
		sipParser = sipmessage.SipParser()
		try:
			msg  = sipParser.parseSIPMessage(data)
		except ESipStackException: 
			logger.debug('ESipStackException when parsing message')
			return

		event = None

		createTransactions = self._sipStack[SipStack.PARAM_CREATE_TRANSACTIONS]
		if createTransactions is None:
			createTransactions = True 

		logger.debug('onData() getting parameter %s: %s', SipStack.PARAM_CREATE_TRANSACTIONS, str(createTransactions))

		# prepare response event
		if isinstance(msg, sipmessage.SipRequest):

			# identify (match) dialog
			dialog = None

			# check for the required headers.
			topMostVia = msg.getTopmostViaHeader()
			msg.checkHeaders()

			# server transaction
			serverTransaction = None
			if createTransactions:
				# create server transaction
				serverTransaction = self.__sipStack.newSipServerRequest(msg)

				print serverTransaction

			# create new ResponseEvent
			event = SipRequestEvent(self, msg, serverTransaction, dialog)

		elif isinstance(msg, sipmessage.SipResponse):


			topVia = msg.getTopmostViaHeader()

			# identify (match) client transaction
			clientTransaction = None
			if createTransactions:
				clientTransaction = self.__sipProvider.getSipStack().getClientTransactionForResponse(msg)

				if not clientTransaction is None:
					if msg.getStatusCode() >= 200 and msg.getStatusCode() <= 699:
						clientTransaction.setState(Sip.TRANSACTION_STATE_COMPLETED)
					elif msg.getStatusCode() >= 100 and msg.getStatusCode() <= 199:
						clientTransaction.setState(Sip.TRANSACTION_STATE_PROCEEDING)

			# identify (match) dialog
			dialog = None

			# create new ResponseEvent
			event = SipResponseEvent(self, msg, clientTransaction, dialog)

		# notify listeners
		for listener in self._sipStack.getSipListeners():
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
		result.setHost(self.getIpAddress())
		result.setProtocol(self.getTransport())
		result.setPort(self.getPort())

		logger.debug('getViaHeader() Leave')

		return result

class IpDispatcher(object):

	LOGGER_NAME = 'ipdispatcher'

	PROTO_TCP = 'tcp'
	PROTO_UDP = 'udp'

	def __init__(self, name = 'ipdispatcher'):

		self.__name = name 

		self.__listeningSockets = []
		self.__outputSockets = []
		self.__processors = []

		# Create event queue
		self.__eventQueue = Queue.Queue(0)

		# Create threads
		self.__workerThread = WorkerThread(self, self.__eventQueue)
		self.__networkThread = IpNetworkThread(self, self.__eventQueue)

	def addListeningSocket(self, s):
		if not isinstance(s, socket.socket):
			raise TypeError()
		self.__listeningSockets.append(s)

	def registerClientSocket(self, s, cs):
		if not isinstance(s, socket.socket) or not isinstance(cs, socket.socket):
			raise TypeError()

		logger = logging.getLogger(self.LOGGER_NAME)

		logger.debug('registering client socket for listening socket')

		for procData in self.__processors:
			# if s is listening socket or one of client sockets
			if s == procData[0]:
				if not cs in procData[2]:
					procData[2].append(cs)
	
	def removeListeningSocket(self, s):
			self.__listeningSockets.remove(s)

	def getListeningSockets(self):
		return self.__listeningSockets

	def createListeningSocket(self, ipProcessor, ipAddress, port, transport):

		if not isinstance(ipProcessor, IpProcessor):
			raise TypeError()

		logger = logging.getLogger(self.LOGGER_NAME)
	
		logger.debug('Creating listening socket (addr=%s, port=%d, transport=%s)', ipAddress, port, transport)

		s = None
	
		if transport.lower() == 'tcp':
			logger.debug('Creating listening TCP socket')
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.bind((ipAddress, port))
			s.listen(5)

		elif transport.lower() == 'udp':
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.bind((ipAddress, port))

		if not s is None:
			self.addListeningSocket(s)
			self.__processors.append((s, ipProcessor, []))
			logger.debug('socket created and added to list of listening sockets')
			
		# check if instance of network thread should be created
		if len(self.__listeningSockets) > 0:
			logger.debug('Sending event to network thread')
			syncEvent = self.__networkThread.getSyncEvent()
			syncEvent.set()

		

	def createSendingSocket(self, ipAddress, port, transport):

		logger = logging.getLogger(self.LOGGER_NAME)
	
		logger.debug('Creating sending socket (addr=%s, port=%d, transport=%s)', ipAddress, port, transport)
	
		if transport.lower() == 'tcp':
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.bind((ipAddress, port))

		elif transport.lower() == 'udp':
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.bind((ipAddress, port))
		else:
			raise ESipTransportNotSupported(transport)

		logger.debug('Creatied new sending socket (fileno=%d)', s.fileno())
		
		return s

	def getProcessorForSocket(self, s):

		logger = logging.getLogger(self.LOGGER_NAME)
	
		result = None

		logger.debug("searching processor for socket (filno=%d) ", s.fileno())
		for procData in self.__processors:
			# if s is listening socket or one of client sockets
			if s == procData[0] or s in procData[2]:
				result = procData[1] 
		return result 

	def sendSync(self, srcIpAddress, srcPort, dstIpAddress, dstPort, data, transport = 'udp'):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('sendSync() Enter')
		logger.debug('Sending data synchronously srcIp=%s srcPort=%d dstIp=%s, dstPort=%d, transport=%s', srcIpAddress, srcPort, dstIpAddress, dstPort, transport)
		
		s = self.createSendingSocket(srcIpAddress, srcPort, transport)	
			
		if transport.lower() == IpDispatcher.PROTO_UDP:
			logger.debug('Sending data over UDP: %d bytes', len(data))
			s.sendto(data, (dstIpAddress, dstPort))
		elif transport.lower() == IpDispatcher.PROTO_TCP:
			logger.debug('Sending data over UDP: %d bytes', len(data))
			s.connect((dstIpAddress, dstPort))
			s.send(data)
			s.close()
		else:
			raise ESipTransportNotSupported("Unkonwn transport: %s" % transport)

		logger.debug('sendSync() Leave')

	def start(self):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('start() Enter')

		# Start threads
		self.__workerThread.start()
		self.__networkThread.start()

		logger.debug('start() Leave')

	def stop(self):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('stop() Enter')

		# stop threads 
		self.__workerThread.stop()
		self.__networkThread.stop()

		self.__workerThread.join()
		self.__networkThread.join()
		
		logger.debug('stop() Leave')

#### ip networking thread #################################
class IpNetworkThread(threading.Thread):

	LOGGER_NAME = 'ip_network_thread'

	def __init__(self, ipDispatcher, queue):
		self.__ipDispatcher = ipDispatcher
		self.__queue = queue	
		self.__syncEvent = threading.Event()
		threading.Thread.__init__(self)
		self.__running = False
		self.__clientSockets = []

	def getSyncEvent(self):
		return self.__syncEvent

	def stop(self):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('stop()')
		
		self.__running = False
		self.__syncEvent.set()

 
	def run(self):
		logger = logging.getLogger(self.LOGGER_NAME)

		logger.debug('Starting network thread' + self.getName())

		self.__running = True 

		while self.__running:

			logger.debug('Main loop iteration')
				
			# we have nothing to do with empty list of sockets
			# go to sleep and wait to wakeup when something is changed
			# in ip dispatcher configuration
			while True:
				inputSockets = self.__clientSockets + self.__ipDispatcher.getListeningSockets()
				if len(inputSockets) > 0: break
				if (not self.__running): break 
				logger.debug('after conditions')
				self.__syncEvent.clear()
				self.__syncEvent.wait()

			# thread could be stopped in previous loop 
			if (not self.__running): break 
		
			logger.debug('select iteration for %d sockets',len(inputSockets))

			try:
				(in_, out_, exc_) = select.select(inputSockets, [] , [], 1)
			except select.error, e:
				logger.debug('Network error')
				break	

			for fd in in_:
				processor = self.__ipDispatcher.getProcessorForSocket(fd)
				if fd in self.__ipDispatcher.getListeningSockets():
					if fd.type == socket.SOCK_DGRAM:
						logger.debug('Reading data from UDP socket')
						data = fd.recv(1024)
						logger.debug('Finished reading from UDP socket: %d bytes', len(data))
						event = WorkerEventData(data, processor)
						self.__queue.put(event)

					elif fd.type == socket.SOCK_STREAM:
						clientSocket, address = fd.accept()
						logger.debug('Incoming tcp connection %d from %s', clientSocket.fileno(), address)
						self.__clientSockets.append(clientSocket)
						self.__ipDispatcher.registerClientSocket(fd, clientSocket)
				else:
					logger.debug('Reading data from %d', fd.fileno())
					data = fd.recv(1024)
					if data:
						while True:
							dataChunk = fd.recv(1024)
							if not dataChunk: break
							data += dataChunk

						logger.debug('Finished reading from TCP socket: %d bytes', len(data))
						event = WorkerEventData(data, processor)
						self.__queue.put(event)
					else:
						logger.debug('Connection to %d closed', fd.fileno())
						fd.close()
						if fd in self.__clientSockets:
							self.__clientSockets.remove(fd)
						else:
							self.__ipDispatcher.removeListeningSocket(fd)

						
			for fd in out_:
				pass
				
			for fd in exc_:
				pass

		logger.debug('Finishihg network thread' + self.getName())

#### worker thread ########################################

class IWorkerEvent(object):
	"""Abstract class for all Worker events"""
	pass

class WorkerEventData(IWorkerEvent):
	"""Data event"""

	def __init__(self, data = None, processor = None):
		self.__data = data 
		self.__processor = processor 

	def setData(self, data):
		self.__data = data 

	def getData(self):
		return self.__data

	def getProcessor(self):
		return self.__processor

class WorkerEventStop(IWorkerEvent):
	"""Thread stop event"""
	pass

		
class WorkerThread(threading.Thread):
	"""Worker thread implementation"""

	LOGGER_NAME = 'working_thread'

	def __init__(self, ipDispatcher, queue):
		self.__ipDispatcher = ipDispatcher
		self.__queue = queue	
		threading.Thread.__init__(self)

	def stop(self):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('stop()')
	
		event = WorkerEventStop()
		self.__queue.put(event)	

	def run(self):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('Starting worker thread' + self.getName())

		running = True
		while running:

			# Get a client out of the queue
			event = self.__queue.get()

			# Check if we actually have an actual client in the client variable:
			if event == None: continue

			if isinstance(event, WorkerEventData):
				logger.debug("Data event, data:\n--------------------\n%s\n--------------------", event.getData())

				processor = event.getProcessor() 

				if not processor is None:
					processor.onData(event.getData())

			elif isinstance(event, WorkerEventStop):
				running = False

		logger.debug('Finishihg worker thread' + self.getName())





class SipStack(dict):
	"""This class represents the SIP protocol stack.

	This SipStack defines the methods that are to be used by an application implementing the SipListener
	interface to control the architecture and setup of the SIP stack. These methods include:

	* Creation/deletion of SipProvider's that represent messaging objects that can be used by an
	  application to send Request and Response messages statelessly or statefully (via Client and Server transactions).
	* Creation/deletion of Transports that represent different network gateways (ipaddress:port) that a SipProvider can
	  use to send and receive messages. 

	Architecture:
	This specification mandates a one-to-many relationship between a SipStack and a SipProvider. There is
	a one-to-many relationship between a SipStack and a ListeningPoint.

	SipStack Creation
	An application must create a SipStack by invoking the createSipStackmethod, ensuring the setPathName is set.
	Following the naming convention defined in SipFactory, the implementation of the SipStack interface must be
	called SipStackImpl. This specification also defines a stack configuration mechanism using java.util.Properties,
	therefore this constructor must also accept a properties argument:
	"""

	LOGGER_NAME = 'sip_stack'

	STATE_STOPPED = 0
	STATE_RUNNING = 1

	# name of the stack
	PARAM_STACK_NAME = 'stackname'
	# Sets the outbound proxy of the SIP Stack. The fromat for this string is "ipaddress:port/transport"
	# i.e. 129.1.22.333:5060/UDP. This property is optional. 
	PARAM_OUTBOUND_PROXY = 'outboundproxy'
	PARAM_REGISTRAR = 'registrar'
	PARAM_CREATE_TRANSACTIONS = 'create_transactions'
	PARAM_CREATE_DIALOGS = 'create_dialogs'

	TRANSPORT_UDP = "udp"
	TRANSPORT_TCP = "tcp"

	MTU = 1500
	MESSAGE_MAX_LENGTH = MTU - 200

	def __init__(self, properties = None):
		dict.__init__(self)
		self[SipStack.PARAM_CREATE_TRANSACTIONS] = False
		self[SipStack.PARAM_CREATE_DIALOGS] = False

		self._state = self.STATE_STOPPED
		self._listeningPoints = {}
		self._clientTransactions = [] 
		self._serverTransactions = {} 
		self._sipListeners = []

		# process properties
		if properties is None or not type(properties).__name__ == 'dict':
			raise ESipStackInvalidArgument()
		if not SipStack.PARAM_STACK_NAME in properties:
			raise ESipStackException('Missing mandatory parameter: %s' % SipStack.PARAM_STACK_NAME)
		for paramName in properties.keys():
			self[paramName] = properties[paramName]

		# configure logging
		filename = self[SipStack.PARAM_STACK_NAME] + '.log'
		logging.basicConfig(level=logging.DEBUG, filename=filename, filemode="w")

		# create ip dispatcher
		self._ipDispatcher = IpDispatcher()


	def getSipListeners(self):
		return self._sipListeners
	
	def getIpDispatcher(self):
		return self._ipDispatcher

	def addSipListener(self, sipListener):
		self._sipListeners.append(sipListener)


	def start(self):
		"""This method initiates the active processing of the stack."""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('start() Enter')

		self._ipDispatcher.start()
		self._state = SipStack.STATE_RUNNING

		logger.debug('start() Leave')

	def stop(self):
		"""This methods initiates the shutdown of the stack."""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('stop() Enter')

		self._ipDispatcher.stop()
		self._state = SipStack.STATE_STOPPED

		logger.debug('stop() Leave')

	def getState(self):
		return self._state

	def isRunning(self):
		return self._state == SipStack.STATE_RUNNING

	def getNextHop(self, request):

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('getNextHop() Enter')

		result =  None

		# 1. try Route headers
		# TODO	

		# 2. try outbound proxy
		if SipStack.PARAM_OUTBOUND_PROXY in self:
			outboundProxy = self[SipStack.PARAM_OUTBOUND_PROXY]
			result = sipmessage.Hop(outboundProxy)
				
		# 3. try DNS lookup
		if result is None:
			raise ENotImplemented()

		logger.debug('nextHop: %s', result)
		logger.debug('getNextHop() Leave')

		return result

	def addListeningPoint(self, listeningPoint):

		key = listeningPoint.getKey()

		if not key in self._listeningPoints.keys():
			self._listeningPoints[key] = listeningPoint

	def getListeningPointForTransport(self, transport = None):

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('getListeningPointForTransport() Entering, transport=%s', transport)

		result = None

		for lpKey in self._listeningPoints:
			lp = self._listeningPoints[lpKey]
			
			# if transport is None, return first listening point in list
			if transport is None:
				result = lp
				break;

			# if transports are equal, return this listening point 
			if lp.getTransport().lower() == transport.lower():
				result = lp
				break

		lpKey = result.getKey() if not result is None else 'None'

		logger.debug('getListeningPointForTransport() Leaving, result is %s', lpKey)

		return result

	def fixViaHeaders(self, sipMessage, sipListeningPoint):

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('fixViaHeaders() Enter')

		lpVia = sipListeningPoint.getViaHeader()
		topVia = sipMessage.getTopmostViaHeader()

		if topVia is None:
			logger.debug('Adding new Via header generated by listening point')
			sipMessage.addHeader(lpVia)
		else:
			if lpVia.getProtocol() != topVia.getProtocol():
				topVia.setProtocol(lpVia.getProtocol())

			if lpVia.getHost() != topVia.getHost():
				topVia.setHost(lpVia.getHost())

			if lpVia.getPort() != topVia.getPort():
				topVia.setPort(lpVia.getPort())

		logger.debug('fixViaHeaders() Leave')

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
			transport = topVia.getProtocol()

		# find net element where to send request
		nextHop = self.getNextHop(request);
		if nextHop is None:
			raise ETransactionUnavailable('Cannot resolve next hop -- transaction unavailable')

		# modify transport protocol if necessary
		if transport == SipStack.TRANSPORT_UDP and len(str(request)) > SipStack.MESSAGE_MAX_LENGTH:
			transport = Sip.TRANSPORT_TCP

		logger.debug('next hop identified, transport is %s, hop is %s', transport, str(nextHop))

		# look for listening point to be used for sending a message
		lp = self.getListeningPointForTransport(transport)
		if lp is None:
			lp = self.getListeningPointForTransport()
		if lp is None:
			raise ESipStackNoListeningPoint('No listening point available')

		self.fixViaHeaders(request, lp)

		message = str(request)

		localIpAddress = lp.getIpAddress()
		localPort = lp.getPort()

		logger.debug('  local address: %s', localIpAddress)
		logger.debug('  local port: %d', localPort)
		logger.debug('  dst IP: %s', nextHop.getHost())
		logger.debug('  dst port: %d', nextHop.getPort())
		logger.debug('  msg length: %d', len(message))
		logger.debug('  transport: %s', transport)

		logger.debug('sending message: %s', message)

		ipDispatcher = self.getIpDispatcher()
		ipDispatcher.sendSync(
			localIpAddress,
			0,
			nextHop.getHost(),
			nextHop.getPort(),
			message,
			transport)

		logger.debug('sendRequest() Leave')

	def sendResponse(self, response):
		"""Sends the Response statelessly, that is no transaction record is associated with this action.
		This method implies that the application is functioning as either a stateless proxy or a stateless UAS.""" 

		logger = logging.getLogger(self.LOGGER_NAME)

		logger.debug('sendResponse() Enter')

		# get top via header 
		topVia = response.getTopmostViaHeader()
		if topVia is None:
			raise ESipStackException('No via header in response')

		# get transport
		transport = topVia.getProtocol()

		# check to see if Via has "received paramaeter". If so
		# set the host to the via parameter. Else set it to the Via host.
		dstHost = topVia.getReceived()
		if dstHost is None:
			dstHost = topVia.getHost()

		# Symmetric nat support
		dstPort = topVia.getRPort()
		if dstPort is None:
			dstPort = topVia.getPort()
		if dstPort is None:
			raise ESipStackException('Cannot determine remote port from response')

		# look for listening point to be used for sending a message
		lp = self.getListeningPointForTransport(transport)
		if lp is None:
			lp = self.getListeningPointForTransport()
		if lp is None:
			raise ESipStackNoListeningPoint('No listening point available')

		#localAddress = self.__sipStack.getIpAddress()

		message = str(response)

		localAddress = lp.getIpAddress()
		localPort = lp.getPort()

		logger.debug('  local address: %s', localAddress)
		logger.debug('  local port: %d', localPort)
		logger.debug('  dst address: %s', dstHost)
		logger.debug('  dst port: %d', dstPort)
		logger.debug('  msg length: %d', len(message))
		logger.debug('  transport: %s', transport)

		ipDispatcher = self.getIpDispatcher()
		ipDispatcher.sendSync(localAddress, 0, dstHost, dstPort, message, transport)
		
		logger.debug('sendResponse() Leave')

	def getNewClientTransaction(self, request):

		logger = logging.getLogger(self.LOGGER_NAME)
		
		logger.debug('getNewClientTransaction() Enter')

		# check input parameters
		if request is None:
			raise EInvalidArgument('No Request')

		#if not self.__sipStack.isRunning():
		#	raise EInvalidState('SipStack is not in running state')

		# try to find existing transacation for request
		#if request.getTransaction() != None:
		#	raise EInvalidState('Transaction already assigned to request')
		# TODO

		logger.debug('Could not find existing transaction for ' + request.getFirstLine() + ', creating a new one');

		ct = SipClientTransaction(self, request)

		# Set the brannch id before you ask for a tx.
		# If the user has set his own branch Id and the
		# branch id starts with a valid prefix, then take it.
		# otherwise, generate new one. If branch ID checking has 
		# been requested, set the branch ID.
		branch = None
		topmostViaHeader = request.getTopmostViaHeader()
		if not topmostViaHeader is None:
			branch = topmostViaHeader.getBranch();
			if branch is None or not branch.startswith(Sip.BRANCH_MAGIC_COOKIE):
				branch = SipUtils.generateBranchId()
		if branch is None:
			branch = SipUtils.generateBranchId()
		ct.setBranch(branch);

		# if the stack supports dialogs then
		#if SIPTransactionStack.isDialogCreated(request.getMethod()):
			# create a new dialog to contain this transaction
			# provided this is necessary.
			# This could be a re-invite in which case the dialog is re-used. (but noticed by Brad Templeton)
#			if dialog is None:
#				ct.setDialog(dialog, request.getDialogId(False))
#			elif self.isAutomaticDialogSupportEnabled():
#				sipDialog = sipStack.createDialog(ct);
#				ct.setDialog(sipDialog, request.getDialogId(False))
#		else:
#			if dialog is not None:
#				ct.setDialog(dialog, request.getDialogId(False))
#
		# the provider is the event listener for all transactions.
		#ct.addEventListener(self)

		self._clientTransactions.append(ct)

		logger.debug('getNewClientTransaction() Leave')

		return ct 

####### sip transactions ###############################################

class SipTransaction(object):
	"""Transactions are a fundamental component of SIP. A transaction is a request
	sent by a client transaction to a server transaction, along with all responses
	to that request sent from the server transaction back to the client transactions.
	User agents contain a transaction layer, as do stateful proxies. Stateless proxies
	do not contain a transaction layer. This specification provides the capabilities to
	allow either the SipProvider or SipListener to handle transactional functionality.

	This interface represents a generic transaction interface defining the methods common
	between client and server transactions."""

	# Invite Client transaction: The initial state, "calling", MUST be entered when
	# the application initiates a new client transaction with an INVITE request. 
	TRANSACTION_STATE_CALLING = 'calling' 

	# * Invite Client transaction: If the client transaction receives a provisional
	#   response while in the "Calling" state, it transitions to the "Proceeding" state.
	# * Non-Invite Client transaction: If a provisional response is received while in
	#   the "Trying" state, the client transaction SHOULD move to the "Proceeding" state.
	# * Invite Server transaction: When a server transaction is constructed for a request,
	#   it enters the initial state "Proceeding".
	# * Non-Invite Server transaction: While in the "Trying" state, if the application passes
	#   a provisional response to the server transaction, the server transaction MUST enter the "Proceeding" state. 
	TRANSACTION_STATE_PROCEEDING = 'proceeding' 

	# The "Completed" state exists to buffer any additional response retransmissions
	# that may be received, which is why the client transaction remains there only for unreliable transports.
	# * Invite Client transaction: When in either the "Calling" or "Proceeding" states, reception of
	#   a response with status code from 300-699 MUST cause the client transaction to transition to "Completed".
	# * Non-Invite Client transaction: If a final response (status codes 200-699) is received while in
	#   the "Trying" or "Proceeding" state, the client transaction MUST transition to the "Completed" state.
	# * Invite Server transaction: While in the "Proceeding" state, if the application passes
	#   a response with status code from 300 to 699 to the server transaction, the state machine MUST enter the "Completed" state.
	# * Non-Invite Server transaction: If the application passes a final response (status codes 200-699)
	#   to the server while in the "Proceeding" state, the transaction MUST enter the "Completed" state. 
	TRANSACTION_STATE_COMPLETED = 'completed' 

	# The purpose of the "Confirmed" state is to absorb any additional ACK messages that arrive,
	# triggered from retransmissions of the final response. Once this time expires the server
	# MUST transition to the "Terminated" state.
	# * Invite Server transaction: If an ACK is received while the server transaction is in the
	# "Completed" state, the server transaction MUST transition to the "Confirmed" state. 
	TRANSACTION_STATE_CONFIRMED = 'completed' 

	# The transaction MUST be available for garbage collection the instant it enters the "Terminated" state.
	# * Invite Client transaction: When in either the "Calling" or "Proceeding" states, reception of
	#   a 2xx response MUST cause the client transaction to enter the "Terminated" state. If amount of
	#   time that the server transaction can remain in the "Completed" state when unreliable transports
	#   are used expires while the client transaction is in the "Completed" state, the client transaction
	#   MUST move to the "Terminated" state.
	# * Non-Invite Client transaction: If the transaction times out while the client transaction is
	#   still in the "Trying" or "Proceeding" state, the client transaction SHOULD inform the application
	#   about the timeout, and then it SHOULD enter the "Terminated" state. If the response retransmissions
	#   buffer expires while in the "Completed" state, the client transaction MUST transition to the "Terminated" state.
	# * Invite Server transaction: If in the "Proceeding" state, and the application passes a 2xx response
	#   to the server transaction, the server transaction MUST transition to the "Terminated" state. When the
	#   server transaction abandons retransmitting the response while in the "Completed" state, it implies
	#   that the ACK was never received. In this case, the server transaction MUST transition to the "Terminated"
	#   state, and MUST indicate to the TU that a transaction failure has occurred.
	# * Non-Invite Server transaction: If the request retransmissions buffer expires while in the "Completed"
	#   state, the server transaction MUST transition to the "Terminated" state. 
	TRANSACTION_STATE_TERMINATED = 'terminated' 

	# * Non-Invite Client transaction: The initial state "Trying" is entered when
	#   the application initiates a new client transaction with a request.
	# * Non-Invite Server transaction: The initial state "Trying" is entered when
	#   the application is passed a request other than INVITE or ACK. 
	TRANSACTION_STATE_TRYING = 'trying' 



	LOGGER_NAME = 'Transaction'
	
	def __init__(self, sipStack, originalRequest):
		self._applicationData = None
		self._branch = None
		self._dialog = None
		self._originalRequest = originalRequest 
		self._state = None
		self._sipStack = sipStack

	def getApplicationData(self):
		"""Returns the application data associated with the transaction.This specification
		 does not define the format of this application specific data."""
		return self._applicationData

	def setApplicationData(self, applicationData):
		"""This method allows applications to associate application context with the transaction."""
		self._applicationData = applicationData

	def getBranch(self):
		"""Returns a unique branch identifer that identifies this transaction."""
		return self._branch

	def setBranch(self, branch):
		"""Sets a unique branch identifer that identifies this transaction."""
		self._branch = branch


	def getDialog(self):
		"""Gets the dialog object of this transaction object."""
		return self._dialog

	def setOriginalRequest(self, message):
		"""Sets the request message that this transaction handles."""
		self._originalRequest = message 

	def getOriginalRequest(self):
		"""Returns the request that created this transaction."""
		return self._originalRequest

	def getRetransmitTimer(self):
		"""Returns the current value of the retransmit timer in milliseconds used to retransmit
		 messages over unreliable transports for this transaction."""
		raise ENotImplemented()

	def setRetransmitTimer(self, retransmitTimer):
		"""Sets the value of the retransmit timer to the newly supplied timer value."""
		raise ENotImplemented()

	def getSipProvider(self):
		#return this.getMessageProcessor().getListeningPoint().getProvider();
		raise ENotImplemented()

	def getState(self):
		"""Returns the current state of the transaction."""
		return self._state

	def setState(self, state):
		"""Sets new state of the transaction"""

		logger = logging.getLogger(__name__)
		logger.debug('setState(), %s => %s', self._state, state)
		self._state = state


	def terminate(self):
		"""Terminate this transaction and immediately release all stack resources associated with it."""
		raise ENotImplemented()

class SipClientTransaction(SipTransaction):
	""" Client transaction"""

	LOGGER_NAME = 'ClientTransaction'

	def __init__(self, sipStack, request):
		SipTransaction.__init__(self, sipStack, request)

	def createAck(self):
		"""Creates a new Ack message from the Request associated with this client transaction."""
		raise ENotImplemented()

	def createCancel(self):
		"""Creates a new Cancel message from the Request associated with this client transaction."""
		raise ENotImplemented()

	def sendRequest(self):
		"""Sends the Request which created this ClientTransaction.

		Sends the Request which created this ClientTransaction. When an application wishes to send a Request message,
		it creates a Request and then creates a new ClientTransaction from getNewClientTransaction. Calling this method
		on the ClientTransaction sends the Request onto the network. The Request message gets sent via the ListeningPoint
		information of the SipProvider that is associated to this ClientTransaction.

		This method assumes that the Request is sent out of Dialog. It uses the Router to determine the next hop.
		If the Router returns a empty iterator, and a Dialog is associated with the outgoing request of the Transaction
		then the Dialog route set is used to send the outgoing request.

		This method implies that the application is functioning as either a UAC or a stateful proxy, hence the
		underlying implementation acts statefully. 
		"""

		logger = logging.getLogger(self.LOGGER_NAME)

		logger.debug('sendRequest()')

		if not self.getState() is None:
			raise EInvalidState('Request already sent')

		request = self.getOriginalRequest()

		# set the branch id for the top via header.
		topVia = request.getTopmostViaHeader()
                topVia.setBranch(self.getBranch());

		# if this is not the first request for this transaction,
		if self.getState() in [SipTransaction.TRANSACTION_STATE_PROCEEDING, SipTransaction.TRANSACTION_STATE_CALLING]:

			# if this is a TU-generated ACK request,
			if request.getMethod() == Request.METHOD_ACK:

				# send directly to the underlying transport and close this transaction
				if self.isReliable():
					self.setState(SipTransaction.TRANSACTION_STATE_TERMINATED)
				else:
					self.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)

				self.cleanUpOnTimer()
			else:
				self.sipStack.sendRequest(request);

		# if this is the FIRST request for this transaction,
		elif self.getState() is None: 

			# Save this request as the one this transaction is handling 
			#self.setRequest(message); 

			# change to trying/calling state 
			# set state first to avoid race condition.. 
			if request.getMethod() == Sip.METHOD_INVITE:
				self.setState(SipTransaction.TRANSACTION_STATE_CALLING) 
			elif request.getMethod() == Sip.METHOD_ACK:
				# Acks are never retransmitted. 
				self.setState(SipTransaction.TRANSACTION_STATE_TERMINATED)
				# TODO: cleanUpOnTimer(); 
			else:
				self.setState(SipTransaction.TRANSACTION_STATE_TRYING); 

			#TODO if not self.isReliable():
			#TODO	self.enableRetransmissionTimer() 
			# TODO Enable appropriate timers
			
			self._sipStack.sendRequest(request);


###### authentication and authorization stuff ########################################

class Authenticator(object):
	"""A helper class that provides useful functionality for clients that need to authenticate with servers."""

	ALG_MD5 = 'md5'

	LOGGER_NAME = 'authenticator'

	def __init__(self, headerFactory):
		self.__cachedCredentials = []
		self.__headerFactory = headerFactory

	def getAuthorization(self, method, uri, requestBody, authHeader, userCredentials):
		"""Generates an authorization header in response to WwwAuthenticationHeader"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('getAuthorization() Enter')

		qopPreferenceList = { 'auth': 1, 'auth-int': 2} 
	
		# authHeader.getQop() is a quoted _list_ of qop values
		#(e.g. "auth,auth-int") Client is supposed to pick one
		qopList = authHeader.getQop()
		qop = 'auth' 
		qopPreferenceValue = qopPreferenceList[qop]
		if not qopList is None:
			qopTypes = qopList.split(',')
			# select quality of protection according to bsip preference (most secure has higher priority)
			for qopType in qopTypes:
				if qopType.strip() in qopPreferenceList:
					if qopPreferenceList[qopType.strip()] > qopPreferenceValue:
						qopPreferenceValue = qopPreferenceList[qopType.strip()]
						qop = qopType.strip() 

		logger.debug('getAuthorization() selected qop is: %s', qop)

		nc_value = 1 
		cnonce = 'xyz'

		response = MessageDigestAlgorithm.calculateResponse(
			authHeader.getAlgorithm(),
			userCredentials.getHashUserDomainPassword(),
			authHeader.getNonce(),
			nc_value,
			cnonce,
			method,
			uri,
			requestBody,
			qop)

		authorization = None;
		
		if isinstance(authHeader, ProxyAuthenticateHeader):
			authorization = self.__headerFactory.createProxyAuthorizationHeader(authHeader.getScheme())
		else:
			authorization = self.__headerFactory.createAuthorizationHeader(authHeader.getScheme())

		authorization.setScheme(authHeader.getScheme())
		authorization.setUserName(userCredentials.getAuthUserName())
		authorization.setRealm(authHeader.getRealm())
		authorization.setNonce(authHeader.getNonce())
		authorization.setUri(uri)
		authorization.setResponse(response);

			
		if not authHeader.getAlgorithm() is None:
			authorization.setAlgorithm(authHeader.getAlgorithm())

		if not authHeader.getOpaque() is None:
			authorization.setOpaque(authHeader.getOpaque())

		if not qopList is None:
			authorization.setQop(qop)
			authorization.setNC(nc_value)
			authorization.setCNonce(cnonce)

		authorization.setResponse(response)

		logger.debug('getAuthorization() Leave')

        	return authorization


class MessageDigestAlgorithm(object):
	"""The class takes standard Http Authentication details and returns a
	response according to the MD5 algorithm
	"""

    	LOGGER_NAME = 'message_digest_algorithm' 
    
	@staticmethod
	def calculateResponse(
		algorithm,
		hashUserNameRealmPasswd,
		nonce_value,
		nc_value,
		cnonce_value,
		method,
		digest_uri_value,
		entity_body,
		qop_value):
		"""
		Calculates an http authentication response in accordance with rfc2617.

		* param algorithm a string indicating a pair of algorithms (MD5 (default), or MD5-sess) used
		  to produce the digest and a checksum.
		* param hashUserNameRealmPasswd MD5 hash of (username:realm:password)
		* param nonce_value A server-specified data string provided in the challenge.
		* param cnonce_value an optional client-chosen value whose purpose is to foil chosen plaintext attacks.
		* param method the SIP method of the request being challenged.
		* param digest_uri_value the value of the "uri" directive on the Authorization header in the request.
		* param entity_body the entity-body
		* param qop_value Indicates what "quality of protection" the client has applied to the message.
		* param nc_value the hexadecimal count of the number of requests (including the current request)
		  that the client has sent with the nonce value in this request.

		return a digest response as defined in rfc2617
		"""

		logger = logging.getLogger(MessageDigestAlgorithm.LOGGER_NAME)
		logger.debug('calculateResponse() Enter')
		logger.debug('trying to authenticate using: algorithm=%s, credentials_hash=%s, nonce=%s, nc=%s, cnonce=%s, method=%s, digest_uri=%s, datalen=%d, qop=%s',
			algorithm, hashUserNameRealmPasswd, nonce_value, nc_value, cnonce_value, method, digest_uri_value, len(entity_body), qop_value)

		# check required parameters
 		if hashUserNameRealmPasswd is None or  method is None or digest_uri_value is None or nonce_value is None:
			raise EInvalidArgument('Not enought parameters to calculate digest response')

		# The following follows closely the algorithm for generating a response
		# digest as specified by rfc2617
		if cnonce_value is None or len(cnonce_value) == 0:
                	raise EInvalidArgument('cnonce_value may not be absent for MD5-Sess algorithm.')
     
		A2 = None
		if qop_value is None or len(qop_value.strip()) == 0 or qop_value.strip().lower() == 'auth':
			A2 = method + ":" + digest_uri_value
		else:
			if entity_body is None:
				entity_body = ''
			A2 = method + ':' + digest_uri_value + ':' + MessageDigestAlgorithm.H(entity_body);

		request_digest = None;

		if not cnonce_value is None and not qop_value is None and not nc_value is None and qop_value.strip().lower() in ['auth', 'auth-int']:

			request_digest = MessageDigestAlgorithm.KD(hashUserNameRealmPasswd, str(nonce_value) + ':' + str(nc_value) + ':' + str(cnonce_value) + ':' + str(qop_value) + ':' + MessageDigestAlgorithm.H(A2));
		else:
			request_digest = MessageDigestAlgorithm.KD(hashUserNameRealmPasswd, str(nonce_value) + ':' + MessageDigestAlgorithm.H(A2))

		logger.debug('calculateResponse() Leave')

		return request_digest;

	@staticmethod
	def H(data):
		"""Defined in rfc 2617 as H(data) = MD5(data)"""

		m = hashlib.md5()
		m.update(data)
		return m.hexdigest()

	@staticmethod
	def KD(secret, data):
		"""Defined in rfc 2617 as KD(secret, data) = H(concat(secret, ":", data))"""

		return MessageDigestAlgorithm.H(secret + ':' + data)


