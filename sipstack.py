
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
		self._clientTransactions = {} 
		self._serverTransactions = {} 
		self._sipListeners = []
		self._processProperties(properties)
		self._configureLogging()
		self._ipDispatcher = IpDispatcher()

	def _processProperties(self, properties):
		if properties is None or not type(properties).__name__ == 'dict':
			raise ESipStackInvalidArgument()

		if not SipStack.PARAM_STACK_NAME in properties:
			raise ESipStackException('Missing mandatory parameter: %s' % SipStack.PARAM_STACK_NAME)

		for paramName in properties.keys():
			self[paramName] = properties[paramName]

	def _configureLogging(self):
		filename = self[SipStack.PARAM_STACK_NAME] + '.log'
		logging.basicConfig(level=logging.DEBUG, filename=filename, filemode="w")

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

class Authenticator(object):
	"""A helper class that provides useful functionality for clients that need to authenticate with servers."""

	ALG_MD5 = 'md5'

	LOGGER_NAME = 'authenticator'

	def __init__(self, accountManager, headerFactory):
		self.__cachedCredentials = []
		self.__accountManager = accountManager
		self.__headerFactory = headerFactory


	def handleChallenge(self, challengeResponse, challengedTransaction, transactionCreator, cacheTime = 0):
		"""Uses security authority to determinie a set of valid user credentials for
		the specified Response (Challenge) and appends it to the challenged request so
		that it could be retransmitted.

		Parameters:
		 * challengeResponse: the 401/407 challenge response
		 * challengedTransaction: the transaction established by the challenged request
		 * transactionCreator: the SipProvider that we should use to create the new transaction.
		 * cacheTime The amount of time (seconds) for which the authentication helper will keep
		   a reference to the generated credentials in a cache. If you specify -1, then the
		   authentication credentials are cached until you remove them from the cache. If you
		   choose this option, make sure you remove the cached headers or you will have a memory leak.

		Returns: a transaction containing a re-originated request with the necessary authorization header.
		"""

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('handleChallenge() Enter')
		
		challengedRequest = challengedTransaction.getOriginalRequest()

		reoriginatedRequest = None

		# If the challenged request is part of a Dialog and the Dialog is confirmed the re-originated
		# request should be generated as an in-Dialog request. 
		dialog = challengedTransaction.getDialog()
		if not challengedRequest.getToTag() is None or dialog is None or dialog.getState() != Sip.DIALOG_STATE_CONFIRMED:
			reoriginatedRequest = copy.deepcopy(challengedRequest)
		else:
			# Re-originate the request by consulting the dialog. In particular 
			# the route set could change between the original request and the  
			# in-dialog challenge. 
			reoriginatedRequest = challengedTransaction.getDialog().createRequest(challengedRequest.getMethod()); 
			for header in challengedRequest.getHeaders():
				# if new request doesn't have current header type then all headers of this name
				srcHeaders = challengedRequest.getHeadersByName(header.getName())	
				reoriginatedRequest.addHeaders(srcHeaders)

		# remove the branch id so that we could use the request in a new transaction
		topMostVia = reoriginatedRequest.getTopmostViaHeader()
		if not topMostVia is None:
			tomMostVia.setBranch(None)  

		if challengeResponse is None or reoriginatedRequest is None:
			raise EInvalidArgument('A null argument was passed to handle challenge.');
            
		authHeaders = None;

		if challengeResponse.getStatusCode() == Sip.RESPONSE_UNAUTHORIZED:
			authHeaders = challengeResponse.getHeadersByType(WwwAuthenticateHeader)
		elif challengeResponse.getStatusCode() == Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED:
			authHeaders = challengeResponse.getHeadersByType(ProxyAuthenticateHeader)
		else:
                	raise ESipException('Unexpected status code')

		if authHeaders is None:
			raise ESipException('Could not find WWWAuthenticate or ProxyAuthenticate headers');

		# Remove all authorization headers from the request (we'll re-add them from cache)
		reoriginatedRequest.removeHeadersByType(AuthorizationHeader)
		reoriginatedRequest.removeHeadersByType(ProxyAuthorizationHeader)

		# rfc 3261 says that the cseq header should be augmented for the new
		# request. do it here so that the new dialog (created together with
		# the new client transaction) takes it into account.
		# Bug report - Fredrik Wickstrom
		cSeq = reoriginatedRequest.getHeaderByType(SipCSeqHeader)
                cSeq.setSeqNumber(cSeq.getSeqNumber() + 1l)


		# Resolve this to the next hop based on the previous lookup. If we are not using
		# lose routing (RFC2543) then just attach hop as a maddr param.
		#mn if len(challengedRequest.getRouteHeaders()) == 0:
		#mn 	hop = challengedTransaction.getNextHop()
                #mn sipUri = reoriginatedRequest.getRequestUri()
                #mn sipUri.setMAddrParam(hop.getHost())
                #mn if hop.getPort() != -1:
		#mn 	sipUri.setPort(hop.getPort())
            
		retryTran = transactionCreator.getNewClientTransaction(reoriginatedRequest);

		authHeader = None;
		requestUri = challengedRequest.getRequestURI();

		for authHeader in authHeaders:
			realm = authHeader.getRealm()
			authorization = None;

			userCreds = self.__accountManager.getCredentials(challengedTransaction, realm)

			if userCreds is None:
				raise ESipException('Cannot find user creds for the given user name and realm')
			
			sipDomain = userCreds.getSipDomain()

			# we haven't yet authenticated this realm since we were started.
			content = reoriginatedRequest.getContent()
			if content is None:
				content = ''
			authorization = self.getAuthorization(
				reoriginatedRequest.getMethod(),
				str(reoriginatedRequest.getRequestUri()),
                                content,
				authHeader,
				userCreds)
                

			logger.debug('Created authorization header: %s' + str(authorization))

		logger.debug('handleChallenge() Leave')

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
		authorization.setUserName(userCredentials.getUserName())
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


