######## transactions ################

class SipTransaction(object):
    """Transactions base

    This interface represents a generic transaction interface defining the methods common
    between client and server transactions."""

    def __init__(self, sipStack, originalRequest, transport = None):
        self.branch = None

        self.originalRequest = originalRequest 
        self.stack = sipStack
        # transport used for sending/receiving transaction messages
        self.transport = transport
        self.state = None

class SipTransactionClientNonInvite(SipTransaction):
    """ Client transaction"""

    LOGGER_NAME = 'SipClientTransaction'

    def __init__(self, sipStack, request, lp = None):
        SipTransaction.__init__(self, sipStack, request, lp)

    def sendAck(self):
        """Creates a new Ack message from the Request associated with this client transaction."""
        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('sendAck() Enter')

        ackRequest = MessageFactory.createRequestAck(self.getOriginalRequest())
        self._sipStack.sendRequest(ackRequest)

        logger.debug('sendAck() Leave')

    def createCancel(self):
        """Creates a new Cancel message from the Request associated with this client transaction."""
        raise ENotImplemented()

    def sendRequest(self, request = None):
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
        logger.debug('sendRequest() Enter')

        #if not self.getState() is None:
        # raise ESipStackInvalidState('Request already sent')

        request = request if not request is None else self.getOriginalRequest()

        # set the branch id for the top via header.
        topVia = request.getTopViaHeader()
        topVia.setBranch(self.getBranch());

        # if this is not the first request for this transaction,
        if self.getState() in [SipTransaction.TRANSACTION_STATE_PROCEEDING, SipTransaction.TRANSACTION_STATE_CALLING]:

            # if this is a TU-generated ACK request,
            if request.getMethod() == SipRequest.METHOD_ACK:

                # send directly to the underlying transport and close this transaction
                #if self.isReliable():
                self.setState(SipTransaction.TRANSACTION_STATE_TERMINATED)
                self._sipStack.sendRequest(request);

                #else:
                # self.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)

                #self.cleanUpOnTimer()
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
            #TODO self.enableRetransmissionTimer() 
            # TODO Enable appropriate timers
            
            self._sipStack.sendRequest(request);

        logger.debug('sendRequest() Leave')

    def processResponse(self, response):
        logger = logging.getLogger(self.LOGGER_NAME)
        logger.debug('processResponse() Enter in state %s' % self.getState())

        blockListeners = False 

        state = self.getState()
        invTransaction = self.getOriginalRequest().getMethod() == SipRequest.METHOD_INVITE

        # 100 - 199 handle provisioning response
        if response.getStatusCode() >= 100 and response.getStatusCode() <= 199:
            if state in [SipTransaction.TRANSACTION_STATE_CALLING, SipTransaction.TRANSACTION_STATE_TRYING, SipTransaction.TRANSACTION_STATE_PROCEEDING]:
                self.setState(SipTransaction.TRANSACTION_STATE_PROCEEDING)
            else:
                blockListeners = True 

        # 200 - 299 handle ok response
        elif response.getStatusCode() >= 200 and response.getStatusCode() <= 299:
            if invTransaction: 
                if state in [SipTransaction.TRANSACTION_STATE_CALLING, SipTransaction.TRANSACTION_STATE_PROCEEDING]:
                    self.setState(SipTransaction.TRANSACTION_STATE_TERMINATED)
                else:
                    blockListeners = True 
            else:
                if state in [SipTransaction.TRANSACTION_STATE_TRYING, SipTransaction.TRANSACTION_STATE_PROCEEDING]:
                    self.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)
                else:
                    blockListeners = True 

        # 300 - 699 handle ok response
        elif response.getStatusCode() >= 300 and response.getStatusCode() <= 699:
            if invTransaction: 
                self.sendAck()
            if state in [SipTransaction.TRANSACTION_STATE_CALLING, SipTransaction.TRANSACTION_STATE_TRYING, SipTransaction.TRANSACTION_STATE_PROCEEDING]:
                self.setState(SipTransaction.TRANSACTION_STATE_COMPLETED)
            else:
                blockListeners = True 
        else:
            blockListeners = True 

        if blockListeners:
            logger.debug('discarding message %s %s', respnse.getStatusCode(), getReasonPhrase())

        logger.debug('processResponse() Leave')

        return blockListeners 

class SipTranClientState():
    pass

class SipTranClientNonInviteCalling(SipTransaction):
    """Implementation of calling state for non-Invite Client transaction state"""

    LOGGER_NAME = 'SipClientTransaction'

