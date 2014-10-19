
import copy
import logging
import unittest
import hashlib

from sip import Sip, SipUtils
import message
from user import User 

class DigestAuthenticator():
    """A helper class that provides useful functionality for clients that need to authenticate with servers.

    Cache is used to store authorization data for ongoing transactions. Cache is indexed by callId on first
    level and by realm on second level.     
    """

    ALG_MD5 = 'md5'

    LOGGER_NAME = 'BSip.AuthDigest'
    QOP_PREFERENCE_LIST = { 'auth': 1, 'auth-int': 2} 

    def __init__(self, user):
        assert isinstance(user, User), 'No user credentials provided for digest authentication'
        self.cachedCredentials = dict()
        self.user = user
        self.logger = logging.getLogger(self.LOGGER_NAME)

    def handleChallenge(self, response):
        '''Generate new request containing authorization for response with challenge sent by server'''

        assert isinstance(response, message.SipResponse)

        # check correct response code and presence of proper authentication header
        if response.getStatusCode() == Sip.RESPONSE_UNAUTHORIZED: 
            authHeaderClass = message.WwwAuthenticateHeader
        elif response.getStatusCode() == Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED: 
            authHeaderClass = message.ProxyAuthenticateHeader
        else:
            raise SipException('Unknown authentication response code')
        # get all auth headers of given type
        authHeaders = response.getHeadersByType(authHeaderClass)
        # raise exception if no auth headers are present 
        if len(authHeaders) == 0:
            raise SipException('Could not find any auth headers (WWW-Authentication, Proxy-Authentication');
      
        realmsProcessed = 0
        for authHeader in authHeaders:
            authHeaderRealm = authHeader.getRealm()
            self.logger.debug('processing auth header %s (realm: %s)' % (authHeader.__class__.__name__, authHeaderRealm))

            # skip all headers that are already in cache
            if authHeaderRealm in self.cachedCredentials:
                continue

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
            else:
                qop = None
            self.logger.debug('selected qop is: %s', qop)

            # create new authorization record for security domain identified by realm
            authParams = dict({
                'response-code': response.getStatusCode(),
                message.Header.PARAM_QOP: qop,
                message.Header.PARAM_ALGORITHM: authHeader.getAlgorithm(),
                message.Header.PARAM_REALM: authHeader.getRealm(),
                message.Header.PARAM_NONCE: authHeader.getNonce(),
                message.Header.PARAM_NC: authHeader.getNC(),
                message.Header.PARAM_OPAQUE: authHeader.getOpaque(),
                message.Header.PARAM_CNONCE: "xyz"})

            # store record to cache
            cacheId = '%d:%s' % (response.getStatusCode(), authHeaderRealm);
            self.logger.debug('storing authentication params to cache (id: %s)' % cacheId)
            self.cachedCredentials[cacheId] = authParams
            realmsProcessed += 1

        if realmsProcessed == 0:
            self.logger.error('No new authentication data found in challenged SIP response')
            raise SipException('No new authentication data found in challenged SIP response')

    def onMessageReceive(self, msg):
        self.logger = logging.getLogger(self.LOGGER_NAME)
        self.logger.debug('onMessageReceive() Enter')

        result = False

        if isinstance(msg, sipmessage.SipResponse):
            # identify (match) client transaction
            tran = self._sipStack.getClientTransactionForResponse(msg)

            self.logger.debug("preprocessing response: %d %s" % (msg.getStatusCode(),    msg.getReasonPhrase()))
            if tran is None:
                self.logger.debug("leaving, client transaction not available")
                return

            # if received response is of type "some authorization required", we need to generate new
            # request with computed authentication values 
            if msg.getStatusCode() in [SipResponse.RESPONSE_UNAUTHORIZED, SipResponse.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]:
                request = self.handleChallenge(msg, tran.getOriginalRequest())
                tran = self._sipStack.createClientTransaction(request)
                self.logger.debug("creating authentication transaction, response will not be delivered to application")
                tran.sendRequest()
                result = True
            else:
                authInfoHeader = msg.getHeaderByType(AuthenticationInfoHeader)
                # TODO update cache 
                callId = msg.getCallId()
                if not authInfoHeader is None and not callId is None:
                    nextNonce = authInfoHeader.getNextNonce()
                    if callId in self.cachedCredentials:
                        if "last" in self.cachedCredentials[callId]:
                            self.logger.debug("updating old nonce stored for call-id %s read from authentication-info header" % callId)
                            self.cachedCredentials[callId]["last"][Header.PARAM_NONCE] = nextNonce
                            self.cachedCredentials[callId]["last"][Header.PARAM_NC] = 0 

        self.logger.debug('onMessageReceive() Leave')

        return result

    def setAuthenticationHeaders(self, request):
        assert isinstance(request, message.SipRequest)

        # loop over all active realms
        for cacheId in self.cachedCredentials:
            authData =  self.cachedCredentials[cacheId]
            authRealm = authData[message.Header.PARAM_REALM]  
            self.logger.debug('Adding or updating auth headers for realm: %s and status code: %d' % (authRealm, authData['response-code']))
            if authData['response-code'] == Sip.RESPONSE_UNAUTHORIZED: 
                authHeaderClass = message.AuthorizationHeader
            elif authData['response-code'] == Sip.RESPONSE_PROXY_AUTHENTICATION_REQUIRED:
                authHeaderClass = message.ProxyAuthorizationHeader
            else:
                SipException('Unsupported status code for authentication: %d' % authData['response-code'])

            # look for auth header for current realm
            authHeaders = request.getHeadersByType(authHeaderClass)
            authHeader = None
            for ah in authHeaders:
                if ah.getRealm() == authRealm:
                    self.logger.debug('Found authentication header for realm %s' % authRealm)
                    authHeader = ah
                    break
            if authHeader is None:
                self.logger.debug('Adding authentication header')
                authHeader = authHeaderClass()
                request.addHeader(authHeader)

            # increment nonce count
            authData[message.Header.PARAM_NC] = authData[message.Header.PARAM_NC] + 1

            response = MessageDigestAlgorithm.calculateResponse(
                authData[message.Header.PARAM_ALGORITHM],
                self.user.getDigestHash(),
                authData[message.Header.PARAM_NONCE],
                authData[message.Header.PARAM_NC],
                authData[message.Header.PARAM_CNONCE],
                request.getMethod(),
                str(request.getRequestUri()),
                request.getContent(),
                authData[message.Header.PARAM_QOP])

            authHeader.setScheme('Digest')
            authHeader.setUserName(self.user.getDigestUser())
            authHeader.setRealm(authRealm)
            authHeader.setNonce(authData[message.Header.PARAM_NONCE])
            authHeader.setUri(str(request.getRequestUri()))
            authHeader.setResponse(response)

            if not authData[message.Header.PARAM_ALGORITHM] is None:
                authHeader.setAlgorithm(authData[message.Header.PARAM_ALGORITHM])

            if not authData[message.Header.PARAM_OPAQUE] is None:
                authHeader.setOpaque(authData[message.Header.PARAM_OPAQUE])

            if not authData[message.Header.PARAM_QOP] is None:
                authHeader.setQop(authData[message.Header.PARAM_QOP])
                authHeader.setNC(authData[message.Header.PARAM_NC])
                authHeader.setCNonce(authData[message.Header.PARAM_CNONCE])

class MessageDigestAlgorithm():
    """The class takes standard Http Authentication details and returns a
    response according to the MD5 algorithm
    """

    LOGGER_NAME = 'BSip.AuthDigestAlg' 

    @staticmethod
    def calculateResponse(algorithm, hashUserNameRealmPasswd, nonce_value, nc_value, cnonce_value, method, digest_uri_value, entity_body, qop_value):
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

        # check algorithm 
        if not algorithm is None and algorithm != 'MD5':
            raise EInvalidArgument('Only MD5 algorithm is supported')

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

        logger.debug('calculateResponse() Leave (result is: %s)' % request_digest.decode('UTF-8'))

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

#### unit tests ##########################

class UnitTestCase(unittest.TestCase):
    def test01(self):
        da = DigestAuthenticator(None)

def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())



