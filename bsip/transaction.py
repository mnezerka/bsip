import logging
from message import SipRequest
from stack import SipStack, SipTxData, Module
from sip import SipUtils, SipException

class TransactionMgr(Module):
    """Transaction manager"""
    
    ID = 'tranmgr'
    LOGGER_NAME = 'BSip.TranMgr'

    def __init__(self):
        Module.__init__(self)
        self.priority = Module.PRIO_TRANSACTION_LAYER 
        self.transactions = dict()
        self.logger = logging.getLogger(self.LOGGER_NAME)
 
    def getId(self):
        return TransactionMgr.ID 

    # Called on rx response
    def onRxResponse(self, rxData):
        self.logger.debug('Received SIP response: %d %s' % (rxData.msg.getStatusCode(), rxData.msg.getReasonPhrase()))

        # look for transaction
        tranId = rxData.msg.getTransactionId()
        if tranId in self.transactions:
            self.logger.debug('Found transaction for processing SIP response, id: %s' % tranId)
            tran = self.transactions[tranId]
            tran.onRxResponse(rxData)
            return True

        return False
    
    def registerTransaction(self, transaction):
        assert isinstance(transaction, Transaction)
        if transaction.getId() in self.transactions:
            raise SipException('Transaction with id: %s is already registered' % transaction.getId())
        self.transactions[transaction.getId()] = transaction
        self.logger.debug('Registered transaction with id: %s' % transaction.getId())

class TransactionState():
    LOGGER_NAME = 'BSip.TranState.None'
    def __init__(self, transaction):
        assert isinstance(transaction, Transaction)
        self.transaction = transaction
        self.logger = logging.getLogger(self.LOGGER_NAME)

    def getId(self):
        return 'none'

    def onRxResponse(self, rxData):
        raise SipException('Abstract method')

    def onRxRequest(self, rxData):
        raise SipException('Abstract method')

class Transaction():
    """Transactions base class

    Transaction occurs between a client and a server and comprises all messages
    from the first request sent from the client to the server up to a final (non-1xx)
    response sent from the server to the client. If the request is INVITE and the final
    response is a non-2xx, the transaction also includes an ACK to the response. The ACK
    for a 2xx response to an INVITE request is a separate transaction.

    Each transaction is uniquely identified by:
    * branch-id on the Via header (branch id always starts with `z9hG4bK`)
    * Cseq header
    """

    # For UAC, before any message is sent.
    STATE_NEW = 'new' 

    # For UAC, just after request is sent.
    STATE_CALLING = 'calling'

    # For UAS, just after request is received.
    STATE_TRYING = 'trying'

    # For UAS/UAC, after provisional response.
    STATE_PROCEEDING = 'proceeding'

    # For UAS/UAC, after final response.
    STATE_COMPLETED = 'completed'

    # For UAS, after ACK is received.
    STATE_CONFIRMED = 'confirmed'

    # For UAS/UAC, before it is destroyed.
    STATE_TERMINATED = 'terminated'

    # For UAS/UAC, will be destroyed now.
    STATE_DESTROYED = 'destroyed'


    def __init__(self, stack, module, request, destination, transport = None):
        """Constructor"""

        assert isinstance(request, SipRequest)
        assert isinstance(stack, SipStack)
        assert isinstance(module, Module)

        self.logger = logging.getLogger(self.LOGGER_NAME)
       
        # where to send an initial request
        self.destination = destination

        # branch unique for this transaction
        self.branch = None

        # first request that initiated transaction
        self.originalRequest = request 

        # instance of sip stack
        self.stack = stack 

        # module which act as owner of the transactions (is notified of state changes)
        self.module = module

        # transport used for sending/receiving transaction messages
        self.transport = transport

        # instance of the transaction state class
        self.state = TransactionState(self) 

        # last response received
        self.lastResponse = None

    def getId(self):
        return self.originalRequest.getTransactionId()

    def setState(self, state):
        self.logger.debug('State transition: %s -> %s' % (self.state.getId(), state.getId())) 
        self.state = state
        self.module.onTranState(self)

    def getLastStatusCode(self):
        result = None
        if not self.lastResponse is None:
            result = self.lastResponse.getStatusCode()
        return result

######### Non Invite Client Transaction

class TranClientNonInvite(Transaction):
    """Non-Invite client transaction"""

    LOGGER_NAME = 'BSip.TranCliNonInv'

    def __init__(self, stack, module, request, destination, transport = None):
        Transaction.__init__(self, stack, module, request, destination, transport)
        self.branch = SipUtils.generateBranchId()
        self.logger.info('New client (non-invite) transaction, branch: %s', self.branch)

        # look for transport
        if self.transport is None:
            self.transport = self.stack.acquireTransport()

        # fix message according to transport
        self.stack.fixRequestForTransport(self.originalRequest, self.transport)

        # set the branch id for the top via header.
        topVia = self.originalRequest.getTopViaHeader()
        topVia.setBranch(self.branch)

        # register transaction in stack
        transMgr = self.stack.getModule(TransactionMgr.ID)
        if not transMgr is None:
            transMgr.registerTransaction(self)

        self.setState(TranClientNonInviteStateNew(self))

    def sendRequest(self):
        """Sends the Request which created this client transaction"""
        self.state.sendRequest()

    def onRxResponse(self, rxData):
        self.logger.debug('Received SIP response')
        self.state.onRxResponse(rxData)

class TranClientNonInviteStateNew(TransactionState):
    """Transaction state - new"""

    LOGGER_NAME = 'BSip.TranCliNonInv.New'

    def getId(self):
        return Transaction.STATE_NEW 

    def sendRequest(self):
        txData = SipTxData()
        txData.msg = self.transaction.originalRequest
        txData.transport = self.transaction.transport 
        txData.dest = self.transaction.destination

        self.logger.debug('Sending initial request to %s:%d' % (self.transaction.destination))

        try:
            self.transaction.stack.sendStateless(txData)
            # change transaction state
            self.transaction.setState(TranClientNonInviteStateTrying(self.transaction))
        except:
            self.transaction.setState(TranClientTerminated(self.transaction))
            raise
             
    def onRxResponse(self, rxData):
        pass

    def onRxRequest(self, rxData):
        pass

class TranClientNonInviteStateTrying(TransactionState):
    LOGGER_NAME = 'BSip.TranCliNonInv.Trying'

    def getId(self):
        return Transaction.STATE_TRYING

    def onRxResponse(self, rxData):
        self.transaction.lastResponse = rxData.msg
        code = rxData.msg.getStatusCode()
        if code / 100 == 1:
            self.transaction.setState(TranClientNonInviteStateProceeding(self.transaction))
        elif code / 100 in [2, 3, 4, 5, 6]:
            self.transaction.setState(TranClientNonInviteStateCompleted(self.transaction))
        else:
            raise SipException('Unknow response code: %d' % code)

class TranClientNonInviteStateProceeding(TransactionState):

    LOGGER_NAME = 'BSip.TranCliNonInv.Proceeding'

    def getId(self):
        return Transaction.STATE_PROCEEDING

class TranClientNonInviteStateCompleted(TransactionState):

    LOGGER_NAME = 'BSip.TranCliNonInv.Completed'

    def getId(self):
        return Transaction.STATE_COMPLETED

class TranClientNonInviteStateTerminated(TransactionState):

    LOGGER_NAME = 'BSip.TranCliNonInv.Terminated'

    def getId(self):
        return Transaction.STATE_TERMINATED

######### Invite Client Transaction

# TODO


