
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
import copy

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

		self._sipStack.processMessageReceive(msg)

		event = None

		createTransactions = self._sipStack[SipStack.PARAM_CREATE_TRANSACTIONS]
		if createTransactions is None:
			createTransactions = True 

		logger.debug('onData() getting parameter %s: %s', SipStack.PARAM_CREATE_TRANSACTIONS, str(createTransactions))

		# prepare response event
		if isinstance(msg, sipmessage.SipRequest):

			# check for the required headers.
			topMostVia = msg.getTopmostViaHeader()
			msg.checkHeaders()

			# server transaction
			serverTransaction = self._sipStack.getServerTransactionForRequest(msg)

			# TODO: if serverTransaction not None then it is retransmission
				
			if createTransactions and serverTransaction is None:
				serverTransaction = self._sipStack.createServerTransaction(msg)

				#tranId = msg.getTransactionId()
				#logger.debug('onData(), looking for existing server transaction: %s, %s ', tranId, msg.getFirstLine())

			#  modify transaction state according to state machine 
			if not serverTransaction is None:
				if msg.getMethod() in [SipRequest.METHOD_INVITE, SipRequest.METHOD_ACK]:
					serverTransaction.setState(SipTransaction.TRANSACTION_STATE_PROCEEDING)
				else: 
					serverTransaction.setState(SipTransaction.TRANSACTION_STATE_TRYING)

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
				if msg.getStatusCode() >= 200 and msg.getStatusCode() <= 699:
					clientTransaction.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)
				elif msg.getStatusCode() >= 100 and msg.getStatusCode() <= 199:
					clientTransaction.setState(SipTransaction.TRANSACTION_STATE_PROCEEDING)

			# identify (match) dialog
			dialog = None

			# create new ResponseEvent
			event = SipResponseEvent(self, msg, clientTransaction, dialog)

		# allow message preprocessing
		blockListeners = self._sipStack.preprocessSipEvent(event)

		# notify listeners
		if not blockListeners:
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

class SipInterceptor(object):

	def onMessageSend(self, msg):
		pass

	def onMessageReceive(self, msg):
		pass

	def onEvent(self, msg):
		pass

#### sip stack #######################################

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
		self._clientTransactions = {} 
		self._serverTransactions = {} 
		self._sipListeners = []
		self._sipInterceptors = []

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

	def getServerTransactions(self):
		return self._serverTransactions	

	def getIpDispatcher(self):
		return self._ipDispatcher

	def addSipListener(self, sipListener):
		self._sipListeners.append(sipListener)

	def addSipInterceptor(self, preprocessor):
		self._sipInterceptors.append(preprocessor)

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

		# notify all interceptors
		for si in self._sipInterceptors:
			si.onMessageSend(request)

		message = str(request)

		localIpAddress = lp.getIpAddress()
		localPort = lp.getPort()

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

		# notify all interceptors
		for si in self._sipInterceptors:
			si.onMessageSend(request)

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

	def getServerTransactionForRequest(self, request):
		logger = logging.getLogger(self.LOGGER_NAME)
		tranId = request.getTransactionId()
		logger.debug('getServerTransactionForRequest() looking for server transaction identified by %s' % tranId)
		return self._serverTransactions[tranId] if tranId in self._serverTransactions else None

	def getClientTransactionForResponse(self, response):
		"""Find client transaction to be assigned to response
		
		When a response is received, it has to be determine which
		client transaction will handle the response,
			
		A response matches a client transaction under two conditions:

		1.  response.topvia.branch == originalrequest.topvia.branch
		2.  response.cseq_header == originalrequest.method

		This is already covered by method getTransactionId() which uses cseq
		header for computation.

		For more details see sections 17.1.1 and 17.1.2 of sip rfc.
		"""

		logger = logging.getLogger(self.LOGGER_NAME)
		tranId = response.getTransactionId()
		logger.debug('getClientTransactionForResponse() looking for client transaction identified by %s' % tranId)
		return self._clientTransactions[tranId] if tranId in self._clientTransactions else None

	def createClientTransaction(self, request):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('createClientTransaction() Enter')

		# check input parameters
		if request is None:
			raise ESipStackInvalidArgument('No Request')

		#if not self.__sipStack.isRunning():
		#	raise EInvalidState('SipStack is not in running state')


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
                		topmostViaHeader.setBranch(branch);

		if branch is None:
			branch = SipUtils.generateBranchId()

		# get unique transaction identification
		tranId = request.getTransactionId()

		# try to find existing transacation for request
		if tranId in self._clientTransactions:
			raise ESipStackException('Transaction already assigned to request')

		logger.debug('Could not find existing transaction for ' + request.getFirstLine() + ', creating a new one');

		ct = SipClientTransaction(self, request)
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

		logger.debug('createClientTransaction() created new client transaction identified by %s' % tranId)
		self._clientTransactions[request.getTransactionId()] = ct
		logger.debug('createClientTransaction() Leave')

		return ct 

	def createServerTransaction(self, request):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('createServerTransaction() Enter')

		result = None

		# check input parameters
		if request is None:
			raise ESipStackInvalidArgument('Missing request')

		# get unique transaction identification
		tranId = request.getTransactionId()

		# try to find existing transacation for request
		if tranId in self._serverTransactions:
			raise ESipStackException('Transaction already assigned to request')

		result = SipServerTransaction(self, request)
		self._serverTransactions[tranId] = result 
		logger.debug('onData(), created new server transaction: %s, %s ', tranId, request.getFirstLine())
		logger.debug('createServerTransaction() Leave')

		return result
	
	def getTransactionForMessage(self, msg):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('getTransactionForMessage() Enter')
		
		result = None

		via = msg.getTopmostViaHeader()

		if not via is None:
			if not via.getBranch() is None:
				key = msg.getTransactionId()
				if key in self._serverTransactions:
					result = self._serverTransactions[key]
				elif key in self._clientTransactions: 
					result = self._clientTransactions[key]
                        	
		logger.debug('getTransactionForMessage() returning: ' + str(result))
		logger.debug('getTransactionForMessage() Leave')
		return result 
		for si in self._sipInterceptors:
			si.onMessageReceive(request)
		for si in self._sipInterceptors:
			si.onMessageReceive(request)

	def processMessageReceive(self, msg):
		"""Allow all message interceptors to do their work.

		Returns "True" if message shoudln't be processed, else "False" 
		"""

		result = False
		for si in self._sipInterceptors:
			result = result or si.onMessageReceive(msg)
		return result

	def preprocessSipEvent(self, event):
		"""Allow all event preprocessors to do its work.

		Each preprocessor can force stop delivery of event to application

		Returns "True" if message shoudln't be sent to application, else "False" 
		"""

		# default value - event will be delivered to application
		result = False
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('preprocessSipEvent() Enter')
		for si in self._sipInterceptors:
			result = result or si.onEvent(event)
		logger.debug('preprocessSipEvent() Leave')
		return result


####### sip transactions ###############################################

class SipTransaction(object):
	"""Transactions are a fundamental component of SIP. Specifically,
	a SIP transaction consists of a single request and any responses to
	that request, which include zero or more provisional responses and
	one or more final responses.  In the case of a transaction where the
	request was an INVITE (known as an INVITE transaction), the
	transaction also includes the ACK only if the final response was not
	a 2xx response.  If the response was a 2xx, the ACK is not considered
	part of the transaction.

	Transactions have a client side and a server side. The client side
	is known as a client transaction and the server side as a server
	transaction. The client transaction sends the request, and the
	server transaction sends the response.
	
	
	 A transaction is a request
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

	LOGGER_NAME = 'SipTransaction'
	
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

	def getState(self):
		"""Returns the current state of the transaction."""
		return self._state

	def setState(self, state):
		"""Sets new state of the transaction"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('setState(), %s => %s', self._state, state)
		self._state = state

	def terminate(self):
		"""Terminate this transaction and immediately release all stack resources associated with it."""
		raise ENotImplemented()

class SipClientTransaction(SipTransaction):
	""" Client transaction"""

	LOGGER_NAME = 'SipClientTransaction'

	def __init__(self, sipStack, request):
		SipTransaction.__init__(self, sipStack, request)

	def createAck(self):
		"""Creates a new Ack message from the Request associated with this client transaction."""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('createAck() Enter')

		#if changing state to completed, send ACK
		create Ack

		slef.sendMessage(ackRequest)

		# parent method
		SipTransaction.setState(self, state)

		logger.debug('createAck() Leave')

		raise ENotImplemented()

	def createCancel(self):
		"""Creates a new Cancel message from the Request associated with this client transaction."""
		raise ENotImplemented()

	def sendRequest(self):
		"""Sends the Request which created this ClientTransaction.

		When an application wishes to send a Request message,
		it creates a Request and then creates a new ClientTransaction
		by call to createClientTransaction. Calling this method
		on the ClientTransaction sends the Request onto the network. 

		This method assumes that the Request is sent out of Dialog. It uses the Router to determine the next hop.
		If the Router returns a empty iterator, and a Dialog is associated with the outgoing request of the Transaction
		then the Dialog route set is used to send the outgoing request.
		"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('sendRequest()')

		if not self.getState() is None:
			raise ESipStackInvalidState('Request already sent')

		request = self.getOriginalRequest()

		# set the branch id for the top via header.
		topVia = request.getTopmostViaHeader()
                topVia.setBranch(self.getBranch());

		# if this is not the first request for this transaction,
		if self.getState() in [SipTransaction.TRANSACTION_STATE_PROCEEDING, SipTransaction.TRANSACTION_STATE_CALLING]:

			# if this is a TU-generated ACK request,
			if request.getMethod() == SipRequest.METHOD_ACK:

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
			if request.getMethod() == SipRequest.METHOD_INVITE:
				self.setState(SipTransaction.TRANSACTION_STATE_CALLING) 
			elif request.getMethod() == SipRequest.METHOD_ACK:
				# Acks are never retransmitted. 
				self.setState(SipTransaction.TRANSACTION_STATE_TERMINATED)
				# TODO: cleanUpOnTimer(); 
			else:
				self.setState(SipTransaction.TRANSACTION_STATE_TRYING); 

			#TODO if not self.isReliable():
			#TODO	self.enableRetransmissionTimer() 
			# TODO Enable appropriate timers
			
			self._sipStack.sendRequest(request);

	def setState(self, state):
		"""Sets new state of the transaction"""

		logger = logging.getLogger(self.LOGGER_NAME)

		#if changing state to completed, send ACK
		create Ack

		slef.sendMessage(ackRequest)

		# parent method
		SipTransaction.setState(self, state)


class SipServerTransaction(SipTransaction):
	"""Receives Request and sends Response back to client
	
	This interfaces enables an application to send a Response to a recently
	received Request in a transaction stateful way.

	A new server transaction is generated in the following ways:

	 * By the application by invoking the SipStack for Requests that the application wishes to handle.
	 * By the SipStack by automatically populating the server transaction of a RequestEvent for
	   Incoming Requests that match an existing Dialog. Note that a dialog-stateful application is
	   automatically transaction stateful too 

	A server transaction of the transaction layer is represented by a finite state machine that is
	constructed to process a particular request. The transaction
	layer handles application-layer retransmissions, matching of responses to requests, and application-layer timeouts.

	The server transaction Id must be unique within the underlying implementation. This Id is commonly
	taken from the branch parameter in the topmost Via header (for RFC3261 compliant clients), but may
	also be computed as a cryptographic hash of the To tag, From tag, Call-ID header field, the Request-URI
	of the request received (before translation), the topmost Via header, and the sequence number from the
	CSeq header field, in addition to any Proxy-Require and Proxy-Authorization header fields that may be
	present. The algorithm used to determine the id is implementation-dependent.

	For the detailed server transaction state machines refer to Chapter 17 of RFC 3261, the allowable
	transitions are summarized below:

	Invite Transaction:
	Proceeding -> Completed -> Confirmed -> Terminated

	Non-Invite Transaction:
	Trying -> Proceeding -> Completed -> Terminated 
	"""

	LOGGER_NAME = 'SipServerTransaction'

	def __init__(self, sipStack, request):
		SipTransaction.__init__(self, sipStack, request)

	def enableRetransmissionAlerts(self):
		"""Enable the timeout retransmit notifications for the ServerTransaction."""
		pass

	def sendResponse(self, response):
		"""Sends the Response to a Request which is associated with this ServerTransaction.

		Sends the Response to a Request which is associated with this ServerTransaction. When
		an application wishes to send a Response, it creates a Response using the MessageFactory
		and then passes that Response to this method. The Response message gets sent out on the
		network via the ListeningPoint information that is associated with the SipProvider of
		this ServerTransaction.

		This method implies that the application is functioning as either a UAS or a stateful proxy,
		hence the underlying implementation acts statefully. When a UAS sends a 2xx response to an INVITE,
		the server transaction is transitions to the TerminatedState. The implementation may delay
		physically removing ServerTransaction record from memory to catch retransmissions of the
		INVITE in accordance with the reccomendation of http://bugs.sipit.net/show_bug.cgi?id=769 .

		ACK Processing and final response retransmission:
		If a Dialog is associated with the ServerTransaction then when the UAC sends the ACK
		(the typical case for User Agents), the Application (i.e. Listener) will see
		a ServerTransaction corresponding to the ACK and the corresponding Dialog presented to it.
		The ACK will be presented to the Listener only once in this case. Retransmissions of the
		OK and filtering of ACK retransmission are the responsibility of the Dialog layer of this
		specification. However if no Dialog is associated with the INVITE Transaction, the ACK will
		be presented to the Application with a null Dialog in the RequestEvent and there will be no
		Dialog associated with the ACK Transaction (i.e. getDialog returns null). In this case
		(when there is no Dialog associated with the original INVITE or ACK) the Application is
		responsible for retransmission of the OK for the INVITE if necessary (i.e. if it wants to
		manage its own dialog layer and function as a User Agent) and for dealing with retransmissions
		of the ACK. This requires that the three way handshake of an INVITE is managed by the UAS
		application and not the implementation of this specification.

		Note that Responses created via Dialog should be sent using sendReliableProvisionalResponse 
		"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('sendResponse() Enter')

		if response is None:
			raise ESipStackInvalidArgument()

		# check for meaningful response.
		cSeqHeader = response.getHeaderByType(SipCSeqHeader)
		responseMethod = cSeqHeader.getMethod()
		if not responseMethod == self.getOriginalRequest().getMethod():
			raise ESipStackException('CSeq method does not match Request method of request that created the tx.')

		statusCode = response.getStatusCode()

		# 200-class responses to SUBSCRIBE requests also MUST contain an "Expires" header. The
		# period of time in the response MAY be shorter but MUST NOT be longer than specified in
		# the request.
		#		if responseMethod == SipRequest.METHOD_SUBSCRIBE and statusCode / 100 == 2:
		#			if not response.getHeaderByType(SipExpiresHeader) is None:
		#				raise ESipStackException('Expires header is mandatory in 2xx response of SUBSCRIBE')
		#			else:
		#				requestExpires = self.getOriginalRequest().getExpires()
		#				responseExpires = response.getExpires()
		#				# If no "Expires" header is present in a SUBSCRIBE request, the implied default
		#				# is defined by the event package being used.
		#				if not requestExpires is None and responseExpires.getExpires() > requestExpires.getExpires():
		#                    			raise ESipStackException('Response Expires time exceeds request Expires time : See RFC 3265 3.1.1')
		#

		# check for mandatory headers
		if statusCode == Sip.RESPONSE_OK and responseMethod == SipRequest.METHOD_INVITE and response.getHeaderByType(ContactHeader) is None:
			raise ESipStackException('Contact Header is mandatory for the OK to the INVITE')

		#if not self.isMessagePartOfTransaction(response):
		#	raise ESipStackException('Response does not belong to this transaction.')


		# RFC18.2.2. Sending Responses
		# The server transport uses the value of the top Via header field in order
		# to determine where to send a response.  It MUST follow the following process:
		# If the "sent-protocol" is a reliable transport protocol such as TCP or SCTP,
		# or TLS over those, the response MUST be sent using the existing connection
		# to the source of the original request that created the transaction, if that connection is still open.

		#if self.isReliable():
		#	self.getMessageChannel().sendMessage(response)
		#else:

		#via = response.getTopmostViaHeader()
		#print via
		#transport = via.getTransport()
		#		if transport is None:
		#			raise ESipStackException('missing transport!')
		#		port = via.getRPort()
		#		if port is None:
		#			port = via.getPort()
		#		if port is None:
		#			if transport == Sip.TRANSPORT_TLS:
		#				port = 5061
		#			else:
		#				port = 5060

		#if not self.getState() in == SipTransaction.TRANSACTION_STATE_PROCEEDING:
		#	raise ESipStackInvalidState('Transaction assigned Response already sent')

		#self.getOriginalRequest().checkHeaders()

		# Provided we have set the banch id for this we set the BID for the outgoing via.
		#if not originalRequestBranch is None:
		#	response.getTopmostVia().setBranch(self.getBranch())
		#else:
		#	response.getTopmostVia().removeParameter(SipResponse.PARAMETER_BRANCH);

		# make the topmost via headers match identically for the transaction rsponse.
		#if not originalRequestHasPort:
		#	response.getTopmostVia().removePort()

		#  method of the response does not match the request used to
		#  create the transaction - transaction state does not change.
		# send the message to the client. Record the last message sent out.
		self.lastResponse = response
		self.lastResponseStatusCode = response.getStatusCode()

		# modify transaction state according to state machine
		if response.getStatusCode() >= 200 and response.getStatusCode() <= 699:
			# final responses
			self.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)
		elif response.getStatusCode() >= 100 and response.getStatusCode() <= 199:
			# provisional responses
			self.setState(SipTransaction.TRANSACTION_STATE_PROCEEDING)

		self._sipStack.sendResponse(response)

		logger.debug('sendResponse() Leave')

###### authentication and authorization stuff ########################################
class DigestAuthenticator(SipInterceptor):
	"""A helper class that provides useful functionality for clients that need to authenticate with servers."""

	ALG_MD5 = 'md5'

	LOGGER_NAME = 'digestauthenticator'
	QOP_PREFERENCE_LIST = { 'auth': 1, 'auth-int': 2} 

	def __init__(self, sipStack, accountManager):
		self._cachedCredentials = dict()
		self._sipStack = sipStack 
		self._accountManager = accountManager

	def handleChallenge(self, response, originalRequest):
		""" Server sent a challenge and waits for same request with authorization header"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('handleChallenge() Enter')

		authHeader = response.getHeaderByType(WwwAuthenticateHeader)
		if authHeader is None:
			authHeader = response.getHeaderByType(ProxyAuthenticateHeader)
		if authHeader is None:
			raise ESipStackException('Could not find WWWAuthenticate or ProxyAuthenticate header');

		# create new request instance
		request = copy.deepcopy(originalRequest)

		# get user to be used for authentication 
		fromHeader = request.getHeaderByType(SipFromHeader)
		fromUri = fromHeader.getAddress().getUri()
		user = self._accountManager.getUserByUserName(fromUri.getUser())
		if user is None:
			raise ESipStackException('No user credentials provided for authentication')

		# increment cseq
		cSeq = request.getHeaderByType(SipCSeqHeader)
               	cSeq.setSeqNumber(cSeq.getSeqNumber() + 1l)

		# set new tag and branch to avoid of interaction with old transaction(s)
		fromHeader.setTag(SipUtils.generateTag())
		topVia = request.getTopmostViaHeader()
		topVia.setBranch(SipUtils.generateBranchId())

		# take decision what kind of "quality of protection will be used"
		# authHeader.getQop() is a quoted _list_ of qop values(e.g. "auth,auth-int") Client is supposed to pick one
		qopList = authHeader.getQop()
		qop = 'auth' 
		qopPreferenceValue = self.QOP_PREFERENCE_LIST[qop]
		if not qopList is None:
			qopTypes = qopList.split(',')
			# select quality of protection according to bsip preference (most secure has higher priority)
			for qopType in qopTypes:
				if qopType.strip() in self.QOP_PREFERENCE_LIST:
					if self.QOP_PREFERENCE_LIST[qopType.strip()] > qopPreferenceValue:
						qopPreferenceValue = self.QOP_PREFERENCE_LIST[qopType.strip()]
						qop = qopType.strip() 

		logger.debug('getAuthorization() selected qop is: %s', qop)

		# create new authorization record
		authParams = dict({
			"user": user.getUserName(),
			"authusername": user.getAuthUserName(),
			"userauthhash": user.getHashUserDomainPassword(),
			Header.PARAM_QOP: qop,
			Header.PARAM_ALGORITHM: authHeader.getAlgorithm(),
			Header.PARAM_REALM: authHeader.getRealm(),
			Header.PARAM_NONCE: authHeader.getNonce(),
			Header.PARAM_NC: 0,
			Header.PARAM_OPAQUE: authHeader.getOpaque(),
			Header.PARAM_URI: str(request.getRequestUri()),
			"method": request.getMethod(),
			Header.PARAM_CNONCE: "xyz",
			"classname": ProxyAuthorizationHeader if isinstance(authHeader, ProxyAuthenticateHeader) else AuthorizationHeader})

		# store record to cache
		cacheId = "%s@%s" % (fromUri.getUser(), fromUri.getHost())
		if not cacheId in self._cachedCredentials:
			self._cachedCredentials[cacheId] = dict()
		self._cachedCredentials[cacheId][authParams[Header.PARAM_REALM]] = authParams

		logger.debug('handleChallenge() Leave')
		return request

	def createDigestAuthorizationHeader(self, authParams, response):
		"""Helper function for construction authorization header with correct set of parameters"""
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('createAuthorizationHeader() Enter')

		result = authParams["classname"]()
		result.setScheme('Digest')
		result.setUserName(authParams["authusername"])
		result.setRealm(authParams[Header.PARAM_REALM])
		result.setNonce(authParams[Header.PARAM_NONCE])
		result.setUri(authParams[Header.PARAM_URI])
		result.setResponse(response)
			
		if not authParams[Header.PARAM_ALGORITHM] is None:
			result.setAlgorithm(authParams[Header.PARAM_ALGORITHM])

		if not authParams[Header.PARAM_OPAQUE] is None:
			result.setOpaque(authParams[Header.PARAM_OPAQUE])

		if not authParams[Header.PARAM_QOP] is None:
			result.setQop(authParams[Header.PARAM_QOP])
			result.setNC(authParams[Header.PARAM_NC])
			result.setCNonce(authParams[Header.PARAM_CNONCE])

		result.setResponse(response)
		logger.debug('createAuthorizationHeader() Leave')
        	return result 

	def onEvent(self, event):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('onEvent() Enter')

		result = False

		if isinstance(event, SipResponseEvent):
			response = event.getResponse()
			logger.debug("preprocessing response: %d %s" % (response.getStatusCode(),  response.getReasonPhrase()))
			tran = event.getClientTransaction()
			if tran is None:
				logger.debug("leaving, client transaction not available")
				return

			if response.getStatusCode() == 401 or response.getStatusCode() == 407:
				request = self.handleChallenge(response, tran.getOriginalRequest())
				tran = self._sipStack.createClientTransaction(request)
				logger.debug("creating authentication transaction, response will not be delivered to application")
				tran.sendRequest()
				result = True
			else:
				authInfoHeader = response.getHeaderByType(AuthenticationInfoHeader)
				# TODO update cache 
				#callId = response.getCallId() 
				#if not authInfoHeader is None and not callId is None:
				#	nextNonce = authInfoHeader.getNextNonce()
				#	if callId in self._cachedCredentials:
				#		logger.debug("updating old nonce stored for call-id %s read from authentication-info header" % callId)
				#		#self._cachedCredentials[callId]["nonce"] = nextNonce

		logger.debug('onEvent() Leave')

		return result

	def onMessageSend(self, msg):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('onMessageSend() Enter')

		fromHeader = msg.getHeaderByType(SipFromHeader)
		fromUri = fromHeader.getAddress().getUri()
		cacheId = "%s@%s" % (fromUri.getUser(), fromUri.getHost())
		if  cacheId in self._cachedCredentials:
			logger.debug("found cache entry for cache id %s" % cacheId)
			allRealmAuthParams = self._cachedCredentials[cacheId]

			# look for realm
			authorizationHeader = msg.getHeaderByType(AuthorizationHeader)	
			realm = None
			if not authorizationHeader is None:
				# get realm from authorization header
				realm = authorizationHeader.getRealm()
			else:
				# TODO:
				# use first realm from user cache since no other information is available
				for realm in allRealmAuthParams:
					print realm 
					break

			logger.debug("following realm will be used for authorization: %s" % realm)

			if not realm is None and realm in allRealmAuthParams:
				authParams = allRealmAuthParams[realm]
				authParams[Header.PARAM_NC] = authParams[Header.PARAM_NC] + 1
				msg.removeHeadersByType(AuthorizationHeader)

				response = MessageDigestAlgorithm.calculateResponse(
					authParams[Header.PARAM_ALGORITHM],
					authParams["userauthhash"],
					authParams[Header.PARAM_NONCE],
					authParams[Header.PARAM_NC],
					authParams[Header.PARAM_CNONCE],
					authParams["method"],
					authParams[Header.PARAM_URI],
					msg.getContent(),
					authParams[Header.PARAM_QOP])

				authorizationHeader = self.createDigestAuthorizationHeader(authParams, response)
				msg.addHeader(authorizationHeader)
		logger.debug('onMessageSend() Leave')

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
		# fix message body
		if entity_body is None:
			entity_body = ''

		logger.debug('trying to authenticate using: algorithm=%s, credentials_hash=%s, nonce=%s, nc=%s, cnonce=%s, method=%s, digest_uri=%s, datalen=%d, qop=%s',
			algorithm, hashUserNameRealmPasswd, nonce_value, nc_value, cnonce_value, method, digest_uri_value, len(entity_body), qop_value)

		# check required parameters
 		if hashUserNameRealmPasswd is None or method is None or digest_uri_value is None or nonce_value is None:
			raise EInvalidArgument('Not enought parameters to calculate digest response')

		# The following follows closely the algorithm for generating a response
		# digest as specified by rfc2617
		if cnonce_value is None or len(cnonce_value) == 0:
                	raise EInvalidArgument('cnonce_value may not be absent for MD5-Sess algorithm.')
     
		A2 = None
		if qop_value is None or len(qop_value.strip()) == 0 or qop_value.strip().lower() == 'auth':
			A2 = method + ":" + digest_uri_value
		else:
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


