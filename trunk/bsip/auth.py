
###### authentication and authorization stuff ########################################
class DigestAuthenticator():
	"""A helper class that provides useful functionality for clients that need to authenticate with servers.

	Cache is used to store authorization data for ongoing transactions. Cache is indexed by callId on first
	level and by realm on second level.		
	"""

	ALG_MD5 = 'md5'

	LOGGER_NAME = 'BSip.AuthDigest'
	QOP_PREFERENCE_LIST = { 'auth': 1, 'auth-int': 2} 

	def __init__(self, user):
		self.cachedCredentials = dict()
        self.user = user

	def handleChallenge(self, response, originalRequest):
		'''Generate new request containing authorization for response with challenge sent by server'''

		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('handleChallenge() Enter')

		request = None

		# check correct response code and presence of proper authentication header
		if response.getStatusCode() == SipResponse.RESPONSE_UNAUTHORIZED: 
			authHeader = response.getHeaderByType(WwwAuthenticateHeader)
			if authHeader is None:
				raise SipException('Could not find WWWAuthenticate header');
		elif response.getStatusCode() == SipResponse.RESPONSE_PROXY_AUTHENTICATION_REQUIRED: 
			authHeader = response.getHeaderByType(ProxyAuthenticateHeader)
			if authHeader is None:
				raise SipException('Could not find WWWAuthenticate header');
		else:
			logger.debug('handleChallenge() Leave - unknown response %d, nothing to do' % response.getStatusCode())
			return request 

		# create new request instance
		request = copy.deepcopy(originalRequest)

		# get user to be used for authentication 
		fromHeader = request.getHeaderByType(SipFromHeader)
		fromUri = fromHeader.getAddress().getUri()
		if user is None:
			raise SipException('No user credentials provided for digest authentication')

		# increment cseq
		cSeq = request.getHeaderByType(SipCSeqHeader)
		cSeq.setSeqNumber(cSeq.getSeqNumber() + 1)

		# set new tag and branch to avoid of interaction with old transaction(s)
		fromHeader.setTag(SipUtils.generateTag())
		topVia = request.getTopmostViaHeader()
		topVia.setBranch(SipUtils.generateBranchId())

		logger.debug('processing auth header %s (realm: %s)' % (authHeader.__class__.__name__, authHeader.getRealm()))

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
		logger.debug('selected qop is: %s', qop)

		# create new authorization record for security domain identified by realm
		authParams = dict({
			"user": user,
			Header.PARAM_QOP: qop,
			Header.PARAM_ALGORITHM: authHeader.getAlgorithm(),
			Header.PARAM_REALM: authHeader.getRealm(),
			Header.PARAM_NONCE: authHeader.getNonce(),
			Header.PARAM_NC: authHeader.getNC(),
			Header.PARAM_OPAQUE: authHeader.getOpaque(),
			Header.PARAM_URI: str(request.getRequestUri()),
			"method": request.getMethod(),
			Header.PARAM_CNONCE: "xyz"})

		# update existing authorization header or create new one (use realm as key for searching)
		relatedAuthorizationHeader = None
		if isinstance(authHeader, WwwAuthenticateHeader):
			authorizationHeaders = request.getHeadersByType(AuthorizationHeader)
			for authorizationHeader in authorizationHeaders:
				if authorizationHeader.getRealm() == authHeader.getRealm():
					relatedAuthorizationHeader = authorizationHeader
					break
			if relatedAuthorizationHeader is None:
				logger.debug('new AuthorizationHeader was added')
				relatedAuthorizationHeader = AuthorizationHeader()
				request.addHeader(relatedAuthorizationHeader)
				relatedAuthorizationHeader.setScheme('Digest')
				relatedAuthorizationHeader.setRealm(authHeader.getRealm())

		elif isinstance(authHeader, ProxyAuthenticateHeader):
			authorizationHeaders = request.getHeadersByType(ProxyAuthorizationHeader)
			for authorizationHeader in authorizationHeaders:
				if authorizationHeader.getRealm() == authHeader.getRealm():
					relatedAuthorizationHeader = authorizationHeader
					break
			if relatedAuthorizationHeader is None:
				logger.debug('new ProxyAuthorizationHeader was added')
				relatedAuthorizationHeader = ProxyAuthorizationHeader()
				request.addHeader(relatedAuthorizationHeader)
				relatedAuthorizationHeader.setScheme('Digest')
				relatedAuthorizationHeader.setRealm(authHeader.getRealm())

		logger.debug('after header manipulation')

		# store record to cache
		#cacheId = "%s@%s" % (fromUri.getUser(), fromUri.getHost())
		cacheId = request.getCallId()
		if not cacheId in self.cachedCredentials:
			self.cachedCredentials[cacheId] = dict()
		self.cachedCredentials[cacheId][authParams[Header.PARAM_REALM]] = authParams
		self.cachedCredentials[cacheId]['last'] = authParams

		logger.debug('handleChallenge() Leave')
		return request

	def updateAuthorizationHeader(self, authHeader, authParams, response):
		"""Helper function that upldates authorization header from provided set of auth parameters"""
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('updateAuthorizationHeader() Enter')

		user = authParams["user"]

		authHeader.setScheme('Digest')
		authHeader.setUserName(user.getDigestUser())
		authHeader.setRealm(authParams[Header.PARAM_REALM])
		authHeader.setNonce(authParams[Header.PARAM_NONCE])
		authHeader.setUri(authParams[Header.PARAM_URI])
		authHeader.setResponse(response)

		if not authParams[Header.PARAM_ALGORITHM] is None:
			authHeader.setAlgorithm(authParams[Header.PARAM_ALGORITHM])

		if not authParams[Header.PARAM_OPAQUE] is None:
			authHeader.setOpaque(authParams[Header.PARAM_OPAQUE])

		if not authParams[Header.PARAM_QOP] is None:
			authHeader.setQop(authParams[Header.PARAM_QOP])
			authHeader.setNC(authParams[Header.PARAM_NC])
			authHeader.setCNonce(authParams[Header.PARAM_CNONCE])
		authHeader.setResponse(response)
		logger.debug('updateAuthorizationHeader() Leave')

	def onMessageReceive(self, msg):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('onMessageReceive() Enter')

		result = False

		if isinstance(msg, sipmessage.SipResponse):
			# identify (match) client transaction
			tran = self._sipStack.getClientTransactionForResponse(msg)

			logger.debug("preprocessing response: %d %s" % (msg.getStatusCode(),	msg.getReasonPhrase()))
			if tran is None:
				logger.debug("leaving, client transaction not available")
				return

			# if received response is of type "some authorization required", we need to generate new
			# request with computed authentication values 
			if msg.getStatusCode() in [SipResponse.RESPONSE_UNAUTHORIZED, SipResponse.RESPONSE_PROXY_AUTHENTICATION_REQUIRED]:
				request = self.handleChallenge(msg, tran.getOriginalRequest())
				tran = self._sipStack.createClientTransaction(request)
				logger.debug("creating authentication transaction, response will not be delivered to application")
				tran.sendRequest()
				result = True
			else:
				authInfoHeader = msg.getHeaderByType(AuthenticationInfoHeader)
				# TODO update cache 
				callId = msg.getCallId()
				if not authInfoHeader is None and not callId is None:
					nextNonce = authInfoHeader.getNextNonce()
					if callId in self._cachedCredentials:
						if "last" in self._cachedCredentials[callId]:
							logger.debug("updating old nonce stored for call-id %s read from authentication-info header" % callId)
							self._cachedCredentials[callId]["last"][Header.PARAM_NONCE] = nextNonce
							self._cachedCredentials[callId]["last"][Header.PARAM_NC] = 0 

		logger.debug('onMessageReceive() Leave')

		return result

	def onMessageSend(self, msg):
		logger = logging.getLogger(self.LOGGER_NAME)
		logger.debug('onMessageSend() Enter')

		if not isinstance(msg, SipRequest):
			return

		#fromHeader = msg.getHeaderByType(SipFromHeader)
		#fromUri = fromHeader.getAddress().getUri()
		cacheId = msg.getCallId()
		#cacheId = "%s@%s" % (fromUri.getUser(), fromUri.getHost())
		if cacheId in self._cachedCredentials:
			logger.debug("found cache entry for cache id %s" % cacheId)
			allRealmAuthParams = self._cachedCredentials[cacheId]

			authHeaders = msg.getHeadersByType(AuthorizationHeader) + msg.getHeadersByType(ProxyAuthorizationHeader)
			for authHeader in authHeaders:
				realm = authHeader.getRealm()
				logger.debug("processing authorization header identified by realm %s" % realm)
				if not realm is None and realm in allRealmAuthParams:
					logger.debug("realm %s found in cache" % realm)
					authParams = allRealmAuthParams[realm]
					authParams[Header.PARAM_NC] = authParams[Header.PARAM_NC] + 1

					user = authParams["user"]

					response = MessageDigestAlgorithm.calculateResponse(
						authParams[Header.PARAM_ALGORITHM],
						user.getDigestHash(),
						authParams[Header.PARAM_NONCE],
						authParams[Header.PARAM_NC],
						authParams[Header.PARAM_CNONCE],
						msg.getMethod(),
						authParams[Header.PARAM_URI],
						msg.getContent(),
						authParams[Header.PARAM_QOP])

					self.updateAuthorizationHeader(authHeader, authParams, response)

		logger.debug('onMessageSend() Leave')

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

