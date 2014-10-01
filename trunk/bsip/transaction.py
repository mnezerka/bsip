import logging
from message import SipRequest
from stack import SipStack, SipTxData, Module
from sip import SipUtils

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

    def __init__(self, stack, originalRequest, destination, transport = None):
        """Constructor"""

        assert isinstance(originalRequest, SipRequest)
        assert isinstance(stack, SipStack)

        self.logger = logging.getLogger(self.LOGGER_NAME)
       
        # where to send an initial request
        self.destination = destination

        # branch unique for this transaction
        self.branch = None

        # first request that initiated transaction
        self.originalRequest = originalRequest 

        # instance of sip stack
        self.stack = stack 

        # transport used for sending/receiving transaction messages
        self.transport = transport

        # instance of the transaction state class
        self.state = None

    def getId(self):
        return self.originalRequest.getTransactionId()

class TransactionState():
    def getName(self):
        return 'none'

    def onRxResponse(self, rxData):
        pass

    def onRxRequest(self, rxData):
        pass

class TranClientNonInvite(Transaction):
    """Non-Invite client transaction"""

    LOGGER_NAME = 'BSip.TranCliNonInv'

    def __init__(self, stack, request, destination, transport = None):
        Transaction.__init__(self, stack, request, destination, transport)
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

    def sendRequest(self):
        """Sends the Request which created this client transaction"""


        txData = SipTxData()
        txData.msg = self.originalRequest
        txData.transport = self.transport 
        txData.dest = self.destination

        self.logger.debug('Sending initial request to %s:%d' % (self.destination))

        self.stack.sendStateless(txData)

    def onRxResponse(self, rxData):
        self.logger.debug('Received SIP response')
        pass

class TranClientNonInviteStateTrying(TransactionState):
    pass

class TranClientNonInviteStateProceeding(TransactionState):
    pass

class TranClientNonInviteStateCompleted(TransactionState):
    pass

class TranClientNonInviteStateTerminated(TransactionState):
    pass

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

