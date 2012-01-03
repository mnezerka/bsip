#!/usr/bin/python

import unittest
import random
import time
import copy
#import re
#import urlparse

class ESipMessageException(Exception):
	pass

class ESipMessageNotImplemented(ESipMessageException):
	pass

class ESipMessageHeaderInvalid(ESipMessageException):
	pass

class Sip(object):

	# cookie that should be used as a prefix for all branch hashes
	BRANCH_MAGIC_COOKIE = 'z9hG4bK'


  
	@staticmethod
	def getMethodNames():
		result = [SipRequest.METHOD_ACK, SipRequest.METHOD_BYE, SipRequest.METHOD_CANCEL, SipRequest.METHOD_INVITE, SipRequest.METHOD_OPTIONS, SipRequest.METHOD_REGISTER,
			SipRequest.METHOD_INFO, SipRequest.METHOD_PRACK, SipRequest.METHOD_UPDATE, SipRequest.METHOD_SUBSCRIBE, SipRequest.METHOD_NOTIFY, SipRequest.METHOD_MESSAGE, SipRequest.METHOD_REFER]
		return result

	TRANSPORT_UDP = 'udp'
	TRANSPORT_TCP = 'tcp'

	URI_PREFIX_SIP = 'sip'
	URI_PREFIX_SIPS = 'sips'

	@staticmethod
	def getUriPrefixes():
		return [Sip.URI_PREFIX_SIP, Sip.URI_PREFIX_SIPS] 
	
	RESPONSE_TRYING = 100

	RESPONSE_OK = 200

	RESPONSE_UNAUTHORIZED = 401

	RESPONSE_PROXY_AUTHENTICATION_REQUIRED = 407

class SipUtils(object):
	DIGEST_POOL_SIZE = 20

	@staticmethod
	def generateCallIdentifier(address):
		"""Generate a call identifier. This is useful when we want to generate a
		 call identifier in advance of generating a message."""

		rndNumber = random.random() * 1000
		timeStamp = (time.time() % 10) * 100
		result = "%d%d@%s" % (rndNumber, timeStamp, address)

		return result 

	@staticmethod
	def generateTag():
		"""Generate a tag for a FROM header or TO header. Just return a random 4
		digit integer (should be enough to avoid any clashes!) Tags only need to
		be unique within a call.
		"""

		result = int((time.time() * random.random()) * 1000)

		return str(result)


	@staticmethod
	def generateBranchId():
		"""Generate a cryptographically random identifier that can be used to
		generate a branch identifier."""

		rndNumber = random.random() * 1000
		timeStamp = (time.time() % 10) * 100
		result = "%s%d%d" % (Sip.BRANCH_MAGIC_COOKIE, rndNumber, timeStamp)

		return result

	@staticmethod
	def generateSignature():
		"""Generate a cryptographically random identifier"""
		return SipUtils.generateBranchId()

class HttpUtils():
	@staticmethod
	def parseHttpList(s):
		"""Parse lists as described by RFC 2068 Section 2.

		In particular, parse comma-separated lists where the elements of
		the list may include quoted-strings. A quoted-string could
		contain a comma. A non-quoted string could have quotes in the
		middle. Neither commas nor quotes count if they are escaped.
		Only double-quotes count, not single-quotes.
		"""

		res = []
		part = ''
		escape = quote = False

		for cur in s:
			if escape:
				part += cur
				escape = False
				continue
			if quote:
				if cur == '\\':
					escape = True
					continue
				elif cur == '"':
					quote = False
				part += cur
				continue
			if cur == ',':
				res.append(part)
				part = ''
				continue
			if cur == '"':
				quote = True
			part += cur

		# append last part
		if part:
			res.append(part)
			
		return [part.strip() for part in res] 

class Uri(dict):
	SCHEME_SIP = 'sip'

	def __init__(self):
		self._scheme = None
		dict.__init__(self)
			
	def getScheme(self):
		"""Returns the value of the "scheme" of this URI, for example "sip", "sips" or "tel"."""
		return self._scheme

	def setScheme(self, scheme):
		self._scheme = scheme	

	def isSipURI(self):
		"""This method determines if this is a URI with a scheme of "sip" or "sips"."""
		raise ESipMessageNotImplemented()

class SipUri(Uri):
	"""This class represents SIP URIs, that may have either a sip: or sips: scheme. 

	SIP and SIPS URIs are used for addressing. They are similar to email addresses in that
	they are of the form user@host where user is either a user name or telephone number, and
	host is a host or domain name, or a numeric IP address. Additionally, SIP and SIPS URIs may
	contain parameters and headers (although headers are not legal in all contexts). A SipURI can
	be embedded in web pages, business cards or other hyperlinks to indicate that a particular user
	or service can be called via SIP. 

	sip:user:password@host:port;uri-parameters?headers 
	"""

	def __init__(self, str = None):
		Uri.__init__(self)

		self._headers = {}
		self._host = None
		self._mAddr = None
		self._method = None
		self._port = None
		self._transport = None
		self._ttl = -1
		self._user = None
		self._userParam = None
		self._lrParam = False

		if str is not None:

			# schema
			self.setScheme(None)
			for px in Sip.getUriPrefixes():
				if str.startswith(px + ':'):
					self.setScheme(px)
					str = str[len(px) + 1:]
					break	
			if self.getScheme() is None:
				raise ESipMessageException('Unsupported uri scheme')

			# user and password
			sepPos = str.find('@')
			if sepPos != -1:
				self._user = str[:sepPos]
				str = str[sepPos + 1:]

			# host name 
			sepPos = str.find(';')
			if sepPos == -1:
				self._host = str
				str = ''

			if len(str) > 0:
				self._host = str[:sepPos]
				str = str[sepPos + 1:]	

			# check if port is specified
			sepPos = self._host.find(':')
			if sepPos != -1:
				self._host = self._host[:sepPos]
				self._port = self._host[sepPos + 1:]

			# parameters
			if len(str) > 0:
				paramParts = str.split(';')
				
				for paramPart in paramParts:
					paramPair = paramPart.split('=')
					if len(paramPair) != 2:
						raise ESipMessageException('Invalid parameter')
					self[paramPair[0]] = paramPair[1]
					

	def getHeader(self, name):
		"""Returns the value of the named header, or null if it is not set."""
		raise ENotImplemented()

	def setHeader(self, name, value):
		"""Sets the value of the specified header fields to be included in a request constructed from the URI."""
		raise ENotImplemented()

	def getHeaderNames(self):
		"""Returns an Iterator over the String names of all headers present in this SipURI."""
		raise ENotImplemented()

	def getHost(self):
		"""Returns the host part of this SipURI."""
		return self._host
	def setHost(self, host):
		"""Set the host part of this SipURI to the newly supplied host parameter."""
		self._host = host

	def getMAddrParam(self):
		"""Returns the value of the maddr parameter, or None if this is not set."""
		raise ENotImplemented()

	def setMAddrParam(mAddr):
		"""Sets the value of the maddr parameter of this SipURI."""
		raise ENotImplemented()

	def getMethodParam(self):
		"""Returns the value of the method parameter, or null if this is not set."""
		raise ENotImplemented()

	def setMethodParam(method):
		"""Sets the value of the method parameter."""
		raise ENotImplemented()

	def getPort(self):
		"""Returns the port part of this SipURI."""
		raise ENotImplemented()

	def setPort(self, port):
		"""Set the port part of this SipURI to the newly supplied port parameter."""
		self._port = port

	def getTransportParam(self):
		"""Returns the value of the "transport" parameter, or null if this is not set."""
		raise ENotImplemented()

	def setTransportParam(transport):
		"""Sets the value of the "transport" parameter."""
		raise ENotImplemented()

	def getTTLParam(self):
		"""Returns the value of the "ttl" parameter, or -1 if this is not set."""
		raise ENotImplemented()

	def setTTLParam(self, ttl):
		"""Sets the value of the ttl parameter."""
		raise ENotImplemented()

	def getUser(self):
		"""Returns the user part of this SipURI."""
		return self._user

	def setUser(self, user):
		"""Sets the user of SipURI."""
		self._user = user 

	def getUserParam(self):
		"""Returns the value of the userParam, or None if this is not set."""
		raise ENotImplemented()

	def setUserParam(self, userParam):
		"""Sets the value of the user parameter."""
		raise ENotImplemented()
	
	def getUserPassword(self):
		"""Gets user password of SipURI, or null if it is not set."""
		raise ENotImplemented()

	def setUserPassword(self, userPassword):
		"""Sets the user password associated with the user of SipURI."""
		raise ENotImplemented()

	def hasLrParam(self):
		"""Returns whether the the lr parameter is set."""
		raise ENotImplemented()

	def setLrParam(self):
		"""Sets the value of the lr parameter of this SipURI."""
		self._lrParam = True

	def isSecure(self):
		"""Returns true if this SipURI is secure i.e. if this SipURI represents a sips URI."""
		raise ENotImplemented()

	def setSecure(self, secure):
		"""Sets the scheme of this URI to sip or sips depending on whether the argument is true or false."""
		raise ENotImplemented()

	def removePort(self):
		"""Removes the port part of this SipURI."""
		raise ENotImplemented()

	def __str__(self):
		if self.getScheme() is None or  self._host is None:
			raise ESipMessageException('uri attributes (scheme, host) not complete')

		result = self.getScheme() + ':'
	
		# optional userinfo part
		if self._user is not None:	
		 	result += self._user + '@'

		# mandatory host
		result += str(self._host)

		# optional port part
		if self._port is not None:
			result += ':' + str(self._port)

		# parameters
		paramStr = ''
		for pName in self.keys():
			paramStr += ';' + pName + '=' + self[pName]

		result += paramStr
		
		return result 

class SipAddress(object):
	"""This class represents a user's display name and URI address. The display name of
	an address is optional but if included can be displayed to an end-user. The address
	URI (most likely a SipURI) is the user's address. For example a 'To' address of
	To: Bob sip:duke@jcp.org would have a display name attribute of Bob and an address
	of sip:duke@jcp.org. 

	Examples:
        sip:bob@beloxi.com
        Bob <sip:bob@beloxi.com>
	"""

	def __init__(self, str = None):
		self.__displayName = None
		self.__uri = None

		if str is not None:

			parts = str.strip().split('<', 1)
			
			# if display name is present
			if len(parts) > 1:
				# display name cannot be empty
				if len(parts[0]) > 0:
					# remove "bad" characters from display name
					self.__displayName = parts[0].replace('"', '').strip()
					userAddr = parts[1]
				else:
					userAddr = parts[1]
			else:
				userAddr = parts[0]

			if userAddr.find('>') != -1:
				userAddr = userAddr[:userAddr.find('>')] 

			if userAddr.startswith('sip'):
				self.__uri = SipUri(userAddr)
			elif userAddr.startswith('tel'):
				self.__uri = TelUri(userAddr)
			else:
				raise ESipMessageException
					

	def getDisplayName(self):
		"""Gets the display name of this Address, or null if the attribute is not set."""
		return self.__displayName

	def setDisplayName(self, displayName):
		"""Sets the display name of the Address."""
		self.__displayName = displayName

	def getUri(self):
		"""Returns the URI of this Address."""
		return self.__uri

	def setUri(self, uri):
		"""Sets the URI of this Address."""
		self.__uri = uri

	def isWildcard(self):
		"""This determines if this address is a wildcard address."""
		pass

	def __str__(self):
		if self.__displayName is None:
			result = str(self.__uri)
		else:
			result = '"' + self.__displayName + '" <' + str(self.__uri) + '>'
		return result

class Hop(object):
	"""Network address (host, port, transport) in format host[:port][;transport=udp|tcp]"""

	def __init__(self, str = None):
		self._host = None
		self._port = None
		self._transport = None
		if not str is None:
			self.parse(str)

	def parse(self, str):

		if str is not None:
			parts = str.split(':', 1)

			if len(parts) == 1:
				self._host = parts[0]

			elif len(parts) == 2 and parts[1].isdigit():
				self._host = parts[0]
				self._port = int(parts[1])

	def getHost(self):
		return self._host
 
	def setHost(self, host):
		self._host = host

	def getPort(self):
		return self._port

	def setPort(self, port):
		self._port = port

	def getTransport(self):
		return self._transport

	def setTransport(self, transport):
		self._transport = transport 

	def __str__(self):

		result = self._host

		if not self._port is None:
			result += ':' + str(self._port)
		if not self._transport is None:
			result += ';transport=' + self._transport

		return result

######## headers ################3

class MediaType(object):
	"""This class represents media type methods for any header that contain content type and content sub-type values."""

	def __init__(self, body = None):
		self._contentType = None
		self._contentSubType = None

		if body is not None:
			(type, sep, subType) = body.partition('/')
			if len(sep) > 0:
				self._contentType = type.strip()
				self._contentSubType= subType.strip()
			else:
				raise ESipMessageException('Invalid format for media type header')

	def getContentType(self):
		"""Gets media type of Header with Content type."""
		return self._contentType

	def setContentType(self, contentType):
		"""Sets value of media type of Header with Content Type."""
		self._contentType = contentType

	def getContentSubType(self):
		"""Gets media sub-type of Header with Content sub-type."""
		return self._contentSubType

	def setContentSubType(self, contentSubType):
		"""Sets value of media subtype of Header with Content sub-type."""
		self._contentSubType = contentSubType

	def __str__(self):
		result = ''
		if self._contentType is not None and self._contentSubType is not None:
			result = self._contentType + '/' + self._contentSubType
		return result

class Header(object):
	PARAM_ACTION = 'action';
	PARAM_ALERT = 'alert';
	PARAM_ALGORITHM = 'algorithm';
	PARAM_BRANCH = 'branch';
	PARAM_CARD = 'card';
	PARAM_CAUSE = 'cause';
	# If the server sent a qop-header in the WWW-Authenticate header, the client has to provide this value for HTTP digest auth. See the RFC for more details.
	PARAM_CNONCE = 'cnonce';
	PARAM_COOKIE = 'cookie';
	PARAM_DIGEST = 'Digest';
	PARAM_DOMAIN = 'domain';
	PARAM_DURATION = 'duration';
	PARAM_EMERGENCY = 'emergency';
	PARAM_EXPIRES = 'expires';
	PARAM_HANDLING = 'handling';
	PARAM_HIDDEN = 'hidden';
	PARAM_ICON = 'icon';
	PARAM_ID = 'id';
	PARAM_INFO = 'info';
	PARAM_MADDR = 'maddr';
	PARAM_NC = 'nc';
	PARAM_NEXT_NONCE = 'nextnonce';
	# The nonce the server sent for digest auth, sent back by the client. A nonce should be unique for every 401 response for HTTP digest auth.
	PARAM_NONCE = 'nonce';
	# The nonce count value transmitted by clients if a qop-header is also transmitted. HTTP digest auth only.
	PARAM_NONCE_COUNT = 'nc';
	PARAM_NON_URGENT = 'non-urgent';
	PARAM_NORMAL = 'normal';
	# The opaque header from the server returned unchanged by the client. It is recommended that this string be base64 or hexadecimal data. Digest auth only.
	PARAM_OPAQUE = 'opaque';
	PARAM_OPTIONAL = 'optional';
	PARAM_PASSWORD = 'password';
	PARAM_PROXY = 'proxy';
	PARAM_PUBKEY = 'pubkey';
	PARAM_PURPOSE = 'purpose';
	PARAM_Q = 'q';
	PARAM_QOP = 'qop';
	PARAM_REALM = 'realm';
	PARAM_RECEIVED = 'received';
	PARAM_REDIRECT = 'redirect';
	PARAM_RENDER = 'render';
	PARAM_REQUIRED = 'required';
	PARAM_RESPONSE = 'response';
	PARAM_RESPONSE_AUTH = 'rspauth';
	PARAM_RPORT = 'rport';
	PARAM_SESSION = 'session';
	PARAM_SIGNATURE = 'signature';
	PARAM_SIGNED_BY = 'signed-by';
	PARAM_STALE = 'stale';
	PARAM_TAG = 'tag';
	PARAM_TEXT = 'text';
	PARAM_TRANSPORT = 'transport';
	PARAM_TTL = 'ttl';
	PARAM_URGENT = 'urgent';
	PARAM_URI = 'uri';
	PARAM_USERNAME = 'username';
	PARAM_VERSION = 'version';

	def __init__(self, name = None, body = None):
		self.__name = name 
		self.__body = body 

	def __str__(self):
		return str(self.__name) + ': ' + str(self.__body)

	def getName(self):
		return self.__name

	def setName(self, name):
		self.__name = name

	def getBody(self):
		return self.__body

	def setBody(self, body):
		self.__body = body

class AuthenticationInfoHeader(Header, dict):
	"""The AuthenticationInfo header implementation"""

	def __init__(self, body = None):
		Header.__init__(self, 'Authentication-Info', body)
		dict.__init__(self)

		if not body is None:
			# parse address
			params = HttpUtils.parseHttpList(body)
			for param in params:
				(key, sep, value) = param.partition('=')
				if len(sep) == 0:
					raise ESipMessageException("Cannot parse parameter:" + param)
				# remove quotes
				value = value.replace('"', '')
				self[key.strip()] = value.strip()

	def getNextNonce(self):
		"""Returns the Nonce value of this AuthenticationHeader."""
		return self[Header.PARAM_NEXT_NONCE] if Header.PARAM_NEXT_NONCE in self else None

	def setNextNonce(self, nonce):
		"""Sets the Nonce of the AuthenticationHeader to the nonce parameter value."""
		self[Header.PARAM_NEXT_NONCE] = nonce

	def __str__(self):
		result = self.getName() + ': '
	
		params = ''
		for p in self:
			if len(params) > 0:
				params +=', '
			value = self[p]
			if p == Header.PARAM_NC:
				value = str(value)
			else:
				value = '"' + str(value) + '"'
			params += p + '=' + value

		if len(params) > 0:
			result += ' ' + params 

		return result

class AuthenticationHeader(Header, dict):
	"""The generic AuthenticationHeader"""

	def __init__(self, name, body = None):
		Header.__init__(self, name, body)
		dict.__init__(self)

		self._scheme = None

		if not body is None:
			# parse address
			(scheme, sep, parameters) = body.partition(' ')
			
			# parse parameters
			self._scheme = scheme
			if len(sep) > 0:
				params = HttpUtils.parseHttpList(parameters)
				for param in params:
					(key, sep, value) = param.partition('=')
					if len(sep) == 0:
						raise ESipMessageException("Cannot parse parameter:" + param)
					# remove quotes
					value = value.replace('"', '')
					self[key.strip()] = value.strip()

	# override method to handle quoting
	#def setParameter(self, name, value):
	#	Parameters.setParameter(self, name, value)
	
	def getAlgorithm(self):
		"""Returns the Algorithm value of this AuthenticationHeader."""
		return self[Header.PARAM_ALGORITHM] if Header.PARAM_ALGORITHM in self else None

	def setAlgorithm(self, algorithm):
		"""Sets the Algorithm of the AuthenticationHeader to the new algorithm parameter value."""
		self[Header.PARAM_ALGORITHM] = algorithm

	def getCNonce(self):
		"""Returns the CNonce value of this AuthenticationHeader."""
		return self.getParameter(AuthenticationHeader.PARAM_CNONCE)

	def setCNonce(self, cNonce):
		"""Sets the CNonce of the AuthenticationHeader to the cNonce parameter value."""
		self[Header.PARAM_CNONCE] = cNonce

	def getDomain(self):
		"""Returns the Domain value of this AuthenticationHeader."""
		return self.getParameter(AuthenticationHeader.PARAM_DOMAIN)

	def setDomain(self, domain):
		"""Sets the Domain of the AuthenticationHeader to the domain parameter value."""
		self[Header.PARAM_DOMAIN] = domain

	def getNonce(self):
		"""Returns the Nonce value of this AuthenticationHeader."""
		return self[Header.PARAM_NONCE] if Header.PARAM_NONCE in self else None

	def setNonce(self, nonce):
		"""Sets the Nonce of the AuthenticationHeader to the nonce parameter value."""
		self[Header.PARAM_NONCE] = nonce

	def getNC(self):
		"""Returns the NC (Nonce Count) value."""
		return self.get(Header.PARAM_NC)

	def setNC(self, nc):
		"""Sets the NC (Nonce Count)."""
		self[Header.PARAM_NC] = nc

	def getOpaque(self):
		"""Returns the Opaque value of this AuthenticationHeader."""
		return self[Header.PARAM_OPAQUE] if Header.PARAM_OPAQUE in self else None

	def setOpaque(self, opaque):
		"""Sets the Opaque value of the AuthenticationHeader to the new opaque parameter value."""
		self[Header.PARAM_OPAQUE] = opaque

	def getQop(self):
		"""Returns the Qop value of this AuthenticationHeader."""
		return self[Header.PARAM_QOP] if Header.PARAM_QOP in self else None

	def setQop(self, qop):
		"""Sets the MessageQop value of the AuthenticationHeader to the new qop parameter value."""
		self[Header.PARAM_QOP] = qop

	def getRealm(self):
		"""Returns the Realm value of this AuthenticationHeader."""
		return self[Header.PARAM_REALM] if Header.PARAM_REALM in self else None

	def setRealm(self, realm):
		"""Sets the Realm of the AuthenticationHeader to the realm parameter value."""
		self[Header.PARAM_REALM] = realm

	def getResponse(self):
		"""Returns the Response value of this AuthenticationHeader."""
		return self.getParameter(AuthenticationHeader.PARAM_RESPONSE)

	def setResponse(self, response):
		"""Sets the Response of the AuthenticationHeader to the new response parameter value."""
		self[Header.PARAM_RESPONSE] = response

	def getScheme(self):
		"""Returns the scheme of the Response information for this AuthenticationHeader."""
		return self._scheme

	def setScheme(self, scheme):
		"""Sets the scheme of the Response information for this AuthenticationHeader."""
		self._scheme = scheme

	def getStale(self):
		"""Returns the boolean value of the stale parameter of this WWWAuthenticateHeader."""
		return self.getParameter(AuthenticationHeader.PARAM_STALE)

	def setStale(self, stale):
		"""Sets the value of the stale parameter fot the WwwAuthenticateHeader."""
		self[Header.PARAM_STALE] = stale

	def getUri(sefl):
		"""Returns the DigestURI value of this AuthenticationHeader."""
		return self.getParameter(AuthenticationHeader.PARAM_URI)

	def setUri(self, uri):
		"""Sets the URI of the AuthenticationHeader to the uri parameter value."""
		self[Header.PARAM_URI] = uri

	def getUserName(self):
		"""Returns the Username value of this AuthenticationHeader."""
		return self[Header.PARAM_USERNAME] if Header.PARAM_USERNAME in self else None

	def setUserName(self, userName):
		"""Sets the Username of the AuthenticationHeader to the username parameter value."""
		self[Header.PARAM_USERNAME] = userName

	def __str__(self):
		if self._scheme is None:
			raise ESipMessageException('Authorization scheme is mandatory')
		result = self.getName() + ': '
		result += self._scheme
	
		params = ''
		for p in self:
			if len(params) > 0:
				params +=', '
			value = self[p]
			if p == Header.PARAM_NC:
				value = str(value)
			else:
				value = '"' + str(value) + '"'
			params += p + '=' + value

		if len(params) > 0:
			result += ' ' + params 

		return result

class AuthorizationHeader(AuthenticationHeader):
	"""The Authorization header is used when a user agent wishes to authenticate
	itself with a server - usually, but not necessarily, after receiving an UNAUTHORIZED
	Response - by including an AuthorizationHeader with the Request. The AuthorizationHeader
	consists of credentials containing the authentication information of the user agent for
	the realm of the resource being requested.

	This header field, along with Proxy-Authorization, breaks the general rules about multiple
	header field values. Although not a comma- separated list, this header field name may be
	present multiple times, and MUST NOT be combined into a single header line.

	cnonce   - If the server sent a qop-header in the WWWAuthenticate header, the client has to
	           provide this value for HTTP digest auth. See the RFC for more details.
	nc       - The nonce count value transmitted by clients if a qop-header is also transmitted.
	           HTTP digest auth only.
	nonce    - The nonce the server sent for digest auth, sent back by the client. A nonce should be
	           unique for every 401 response for HTTP digest auth.
	opaque   - The opaque header from the server returned unchanged by the client. It is recommended
	           that this string be base64 or hexadecimal data. Digest auth only.
	password - When the authentication type is basic this is the password transmitted by the client, else None.
	qop      - Indicates what "quality of protection" the client has applied to the message for HTTP digest auth.
	realm    - This is the server realm sent back for HTTP digest auth.
	response - A string of 32 hex digits computed as defined in RFC 2617, which proves that the user knows
	           a password. Digest auth only.
	uri      - The URI from Request-URI of the Request-Line; duplicated because proxies are allowed to change
	           the Request-Line in transit. HTTP digest auth only.
	username - The username transmitted. This is set for both basic and digest auth all the time

	For Example:
	Authorization: Digest username="Alice", realm="atlanta.com",
	nonce="84a4cc6f3082121f32b42a2187831a9e",
	response="7587245234b3434cc3412213e5f113a5432" 
	"""

	def __init__(self, body = None):
		AuthenticationHeader.__init__(self, 'Authorization', body)

class ProxyAuthorizationHeader(AuthenticationHeader):
	"""Same meaning as in case of Authorization header"""

	def __init__(self, body = None):
		AuthenticationHeader.__init__(self, 'Proxy-Authorization', body)


class SipAddressHeader(Header, dict):
	"""Abstract class: Sip Address header"""

	def __init__(self, name, body = None):
		Header.__init__(self, name, body)
		dict.__init__(self)
		self.__address = None

		if not body is None:
			# parse address
			(address, sep, parameters) = body.partition(';')

			self.__address = SipAddress(address)

			# parse parameters
			if len(sep) > 0:
				params = parameters.split(';')
				for param in params:
					(key, sep, value) = param.partition('=')
					if len(sep) == 0:
						raise ESipMessageException()
					self[key.strip()] = value.strip()

	def getAddress(self):
		return self.__address

	def setAddress(self, address):
		self.__address = address

	def __str__(self):
		result = str(self.getName()) + ': '
		result += str(self.__address)
		for param in self.keys():
			result += ';' + param + '=' + self[param]
		return result

class SipCallIdHeader(Header):
	def __init__(self, body = None):
		Header.__init__(self, 'Call-Id' , body)
		self.__callId = None
		if body is not None:
			self.__callId = body.strip()

	def getCallId(self):
		"""Returns the Call-Id of CallIdHeader."""
		return self.__callId

	def setCallId(self, callId):
		"""Sets the Call-Id of the CallIdHeader."""
		self.__callId = callId

	def __str__(self):
		result = self.getName() + ': '
		result += self.__callId 
		return result

class SipFromHeader(SipAddressHeader):
	def __init__(self, body = None):
		SipAddressHeader.__init__(self, 'From' , body)
			
	def getTag(self):
		return self.get(Header.PARAM_TAG)

	def setTag(self, tag):
		if tag is None:
			self.pop(Header.PARAM_TAG)
		else:
			self[Header.PARAM_TAG] = tag

class ContactHeader(SipAddressHeader):
	def __init__(self, body = None):
		SipAddressHeader.__init__(self, 'Contact' , body)

class ContentLengthHeader(Header):
	def __init__(self, body = None):
		Header.__init__(self, 'Content-Length' , body)
		self._contentLength = None
		if body is not None:
			if isinstance(body, int):
				self._contentLength = body
			elif isinstance(body, str) and body.isdigit():
				self.__contentLength = int(body)
	
	def getContentLength(self):
		return self.__contentLength

	def setContentLength(self, val):
		self.__contentLength = val

class ContentTypeHeader(Header, MediaType):
	def __init__(self, body = None):
		Header.__init__(self, 'Content-Type' , body)
		MediaType.__init__(self, body)

	def __str__(self):
		result = self.getName() + ': ' + MediaType.__str__(self)
		return result

class ExpiresHeader(Header):
	"""The Expires header field gives the relative time after which the message (or content)
	expires.

	The precise meaning of this is method dependent. The expiration time in an INVITE
	does not affect the duration of the actual session that may result from the invitation.
	Session description protocols may offer the ability to express time limits on the session
	duration, however. The value of this field is an integral number of seconds (in decimal)
	between 0 and (2**32)-1, measured from the receipt of the request. Malformed values
	SHOULD be treated as equivalent to 3600.

	This interface represents the Expires entity-header. The ExpiresHeader is optional in
	both REGISTER and INVITE Requests.

	 * REGISTER - When a client sends a REGISTER request, it MAY suggest an expiration interval
	that indicates how long the client would like the registration to be valid. There are two ways
	in which a client can suggest an expiration interval for a binding: through an Expires header
	field or an "expires" Contact header parameter. The latter allows expiration intervals to be
	suggested on a per-binding basis when more than one binding is given in a single REGISTER request,
	whereas the former suggests an expiration interval for all Contact header field values that do not
	contain the "expires" parameter.

	 * INVITE - The UAC MAY add an Expires header field to limit the validity of the invitation. If the
	time indicated in the Expires header field is reached and no final answer for the INVITE has
	been received, the UAC core SHOULD generate a CANCEL request for the INVITE. 

	Example:
	Expires: 5
	"""
	
	def __init__(self, body = None):
		Header.__init__(self, 'Expires' , body)

		self.__expires = None

		if body is not None and body.isdigit():
			self.__expires = int(body)

	def getExpires(self):
		"""Gets the expires value of the ExpiresHeader."""
		return self.__expires

	def setExpires(self, expires):
		"""Sets the relative expires value of the ExpiresHeader in units of seconds."""
		self.__expires = expires

	def __str__(self):
		result = self.getName() + ': ' + str(self.__expires)
		return result

class MaxForwardsHeader(Header):
	"""The Max-Forwards header field must be used with any SIP method to limit the number
	 of proxies or gateways that can forward the request to the next downstream server.
	  This can also be useful when the client is attempting to trace a request chain that
	   appears to be failing or looping in mid-chain.

	The Max-Forwards value is an integer in the range 0-255 indicating the remaining number
	 of times this request message is allowed to be forwarded. This count is decremented by
	  each server that forwards the request. The recommended initial value is 70.

	This header field should be inserted by elements that can not otherwise guarantee loop
	 detection. For example, a B2BUA should insert a Max-Forwards header field. 
	"""
	
	def __init__(self, body = None):
		Header.__init__(self, 'Max-Forwards' , body)

		self._maxForwards = None

		if body is not None and body.isdigit():
			self._maxForwards = int(body)

	def decrementMaxForwards(self):
		"""This convenience function decrements the number of max-forwards by one."""
		if self._maxForwards is not None:
			self._maxForwards -= 1

	def getMaxForwards(self):
		"""Gets the maximum number of forwards value of this MaxForwardsHeader."""
		return self._maxForwards

	def setMaxForwards(self, maxForwards):
		"""Sets the max-forwards argument of this MaxForwardsHeader to the supplied maxForwards value."""
		self._maxForwards = maxForwards 

	def __str__(self):
		result = self.getName() + ': ' + str(self._maxForwards)
		return result

class SipCSeqHeader(Header):
	def __init__(self, body = None):
		Header.__init__(self, 'CSeq' , body)

		self._method = None
		self._seqNumber = None

		if body is not None:
			(num, sep, method) = body.partition(' ')
			if len(sep) > 0:
				self._seqNumber = int(num.strip())
				self._method = method.strip()
			else:
				raise ESipMessageException('Invalid format for CSeq header')

	def getMethod(self):
		"""Gets the method of CSeqHeader"""
		return self._method

	def setMethod(self, method):
		"""Sets the method of CSeqHeader"""
		self._method = method
			
	def getSeqNumber(self):
		"""Gets the sequence number of this CSeqHeader."""
		return self._seqNumber

	def setSeqNumber(self, seqNumber):
		"""Sets the sequence number value of the CSeqHeader."""
		self._seqNumber = seqNumber

	def __str__(self):
		result = self.getName() + ': '
		result += str(self._seqNumber) + ' ' + self._method
		return result

class SipToHeader(SipAddressHeader):
	def __init__(self, body = None):
		SipAddressHeader.__init__(self, 'To' , body)

	def getTag(self):
		return self.get(Header.PARAM_TAG)

	def setTag(self, tag):
		if tag is None:
			self.pop(Header.PARAM_TAG)
		else:
			self[Header.PARAM_TAG] = tag

class SipViaHeader(Header, dict):
	PARAM_BRANCH = 'branch'
	PARAM_HOST = 'host'
	PARAM_MADDR = 'maddr'
	PARAM_PORT = 'port'
	PARAM_PROTOCOL = 'protocol'
	PARAM_RECEIVED = 'received'
	PARAM_RPORT = 'rport'
	PARAM_TRANSPORT = 'transport'
	PARAM_TTL = 'ttl'

	def __init__(self, body = None):
		Header.__init__(self, 'Via' , body)
		dict.__init__(self)

		if body is not None:
			(address, sep, parameters) = body.partition(';')
			if len(address) == 0:
				raise ESipMessageException	
			if len(sep) == 0:
				parameters = None
			
			# get transport and parameters
			(transport, sep, host) = address.partition(' ')	
			
			if not transport.startswith('SIP/2.0/') or len(sep) == 0:
				raise ESipMessageException	

			# get transport protocol 
			protocol = transport[len('SIP/2.0/'):]	
			if protocol.lower() not in [Sip.TRANSPORT_UDP, Sip.TRANSPORT_TCP]:
				raise ESipMessageException	

			self[SipViaHeader.PARAM_PROTOCOL] = protocol
	
			# get host name and port
			(hostAddress, sep, hostPort) = host.partition(':')
			self[SipViaHeader.PARAM_HOST] = hostAddress
			if hostPort.isdigit():
				self[SipViaHeader.PARAM_PORT] = hostPort

			# parameters
			if parameters is not None:
				pairs = parameters.split(';')
				for pair in pairs:
					(name, sep, value) = pair.partition('=')	
					if len(sep) == 0:
						raise ESipMessageException()
					self[name] = value



	def getBranch(self):
		"""Gets the branch paramater of the SipViaHeader."""
		return self.get(SipViaHeader.PARAM_BRANCH)

	def setBranch(self, branch):
		"""Sets the branch parameter of the SipViaHeader to the newly supplied branch value."""
		if branch is None:
			self.pop(Header.PARAM_BRANCH)
		else:
			self[Header.PARAM_BRANCH] = branch

	def getHost(self):
		"""Returns the host part of this SipViaHeader."""
		return self[SipViaHeader.PARAM_HOST] if SipViaHeader.PARAM_HOST in self else None

	def setHost(self, host):
		"""Set the host part of this SipViaHeader to the newly supplied host parameter."""
		self[SipViaHeader.PARAM_HOST] = host

	def getMAddr(self):
		"""Returns the value of the maddr parameter, or null if this is not set."""
		return self.getParameter(SipViaHeader.PARAM_MADDR)

	def setMAddr(self, mAddr):
		"""Sets the value of the maddr parameter of this SipViaHeader."""
		self.setParameter(SipViaHeader.PARAM_MADDR, mAddr)

	def getPort(self):
		"""Returns the port part of this SipViaHeader."""
		return int(self[SipViaHeader.PARAM_PORT]) if SipViaHeader.PARAM_PORT in self else None

	def setPort(self, port):
		"""Set the port part of this SipViaHeader to the newly supplied port parameter."""
		self[SipViaHeader.PARAM_PORT] = port

	def getProtocol(self):
		"""Returns the value of the protocol used."""
		return self[SipViaHeader.PARAM_PROTOCOL] if SipViaHeader.PARAM_PROTOCOL in self else None

	def setProtocol(self, protocol):
		"""Sets the value of the protocol parameter."""
		self[SipViaHeader.PARAM_PROTOCOL] = protocol

	def getReceived(self):
		"""Gets the received paramater of the SipViaHeader."""
		return self[Header.PARAM_RECEIVED] if Header.PARAM_RECEIVED in self else None

	def setReceived(self, received):
		"""Sets the received parameter of SipViaHeader."""
		self.setParameter(SipViaHeader.RECEIVED, received)

	def getRPort(self):
		"""Returns the rport part of this ViaHeader."""
		return self[Header.PARAM_RPORT] if Header.PARAM_RPORT in self else None

	def setRPort(self, rport):
		"""Set the rport part of this ViaHeader."""
		self.setParameter(SipViaHeader.RPORT, rport)

	def getTransport(self):
		"""Returns the value of the transport parameter."""
		return self[Header.PARAM_TRANSPORT] if Header.PARAM_TRANSPORT in self else None

	def setTransport(self, transport):
		"""Sets the value of the transport."""
		self.setParameter(SipViaHeader.PARAM_TRANSPORT, transport)

	def getTTL(self):
		"""Returns the value of the ttl parameter, or -1 if this is not set."""
		return self.getParameter(SipViaHeader.PARAM_TTL)

	def setTTL(self, ttl):
		"""Sets the value of the ttl parameter."""
		self.setParameter(SipViaHeader.TTL, ttl)

	def __str__(self):
		result = self.getName() + ': '
		result += 'SIP/2.0/' + self.getProtocol().upper() + ' '
		result += self.getHost() 
		if self.getPort() is not None:
			result += ':' + str(self.getPort())

		# other parameters
		for paramName in self.keys():
			# skip parameters used in address
			if paramName in [SipViaHeader.PARAM_HOST, SipViaHeader.PARAM_PORT, SipViaHeader.PARAM_PROTOCOL]:
				continue
			paramValue = self[paramName]
			if not paramValue is None:
				result += ';' + paramName + '=' + paramValue
		return result

class WwwAuthenticateHeader(AuthenticationHeader):
	"""This class represents the WWW-Authenticate response-header.

	A WWW-Authenticate header field value contains an authentication challenge.
	When a UAS receives a request from a UAC, the UAS MAY authenticate the originator
	before the request is processed. If no credentials (in the Authorization header field)
	are provided in the request, the UAS can challenge the originator to provide
	credentials by rejecting the request with a 401 (Unauthorized) status code.
	The WWW-Authenticate response-header field MUST be included in 401 (Unauthorized)
	response messages. The field value consists of at least one challenge that indicates
	the authentication scheme(s) and parameters applicable to the realm.

	algorithm - A string indicating a pair of algorithms used to produce the digest and
	            a checksum. If this is not present it is assumed to be "MD5". If the algorithm
		    is not understood, the challenge should be ignored (and a different one used, if there is more than one).
	domain    - list of URIs that define the protection space. If a URI is an absolute path,
	            it is relative to the canonical root URL of the server being accessed.
	nonce     - A server-specified data string which should be uniquely generated each time
	            a 401 response is made. It is recommended that this string be base64 or hexadecimal data.
	opaque    - A string of data, specified by the server, which should be returned by the client
	            unchanged in the Authorization header of subsequent requests with URIs in the same
		    protection space. It is recommended that this string be base64 or hexadecimal data.
	qop       - A set of quality-of-privacy directives such as auth and auth-int.
	realm     - A string to be displayed to users so they know which username and password to use.
	            This string should contain at least the name of the host performing the authentication
		    and might additionally indicate the collection of users who might have access.
	type      - The type of the auth mechanism. HTTP currently specifies Basic and Digest.

	For Example:
	WWW-Authenticate: Digest realm="atlanta.com", domain="sip:boxesbybob.com",
	qop="auth", nonce="f84f1cec41e6cbe5aea9c8e88d359", opaque="", stale=FALSE, algorithm=MD5 
	"""
	
	def __init__(self, body = None):
		AuthenticationHeader.__init__(self, 'WWW-Authenticate', body)

class ProxyAuthenticateHeader(AuthenticationHeader):
	"""This class represents the Proxy-Authenticate response-header."""

	def __init__(self, body = None):
		AuthenticationHeader.__init__(self, 'Proxy-Authenticate', body)

###### sip messsage parser ############################################################

class SipParser(object):
	@staticmethod
	def parseListHeader(value):
		"""Parse lists as described by RFC 2068 Section 2.

		In particular, parse comma-separated lists where the elements of
		the list may include quoted-strings. A quoted-string could
		contain a comma. A non-quoted string could have quotes in the
		middle. Quotes are removed automatically after parsing.

		>>> parse_list_header('token, "quoted value"')
		['token', 'quoted value']
		"""
		result = []
		for item in _parse_list_header(value):
			if item[:1] == item[-1:] == '"':
				item = unquote_header_value(item[1:-1])
			result.append(item)
		return result

	
	def parseSIPMessage(self, buffer):

		if buffer == None:
			return

		# locate a body
		msgBody = None
		for bodySeparator in ('\r\n\r\n', '\r\r', '\n\n'):
			bodyOffset = buffer.find(bodySeparator)
			if bodyOffset != -1:
				msgBody = buffer[bodyOffset + len(bodySeparator):]
				buffer = buffer[:bodyOffset]
				break


		# split message into lines and put aside start line
		lines = buffer.splitlines()

		if len(lines) < 2:
			raise ESipMessageException()

		# parse first line and get instance of request or response object
		msg = self.parseFirstLine(lines[0])	

        	i = 1
		while i < len(lines):

			if len(lines[i]) == 0:
				break

			if lines[i][0] in (' ', '\t'):
				lines[i - 1] += ' ' + lines[i].strip()
				del lines[i]
			else:
				i += 1

		# parse headers
		contentLengthHeader = None

		for line in lines[1:]:
			try:
				header = self.parseHeader(line)
				if isinstance(header, ContentLengthHeader):
					contentLengthHeader = header
				msg.addHeader(header)
			except ESipMessageHeaderInvalid:
				pass

			except ValueError:
				pass
		
		if contentLengthHeader is not None:
			contentLength = contentLengthHeader.getContentLength()	
			if contentLength != len(msgBody):
				raise ESipMessageException()
		elif msgBody is not None:
			if len(msgBody) > 0:
				raise ESipMessageException("Body without Content-length header found.")

		msg.setContent(msgBody)

		return msg

	def parseFirstLine(self, str):

		result = None

		methodNames = Sip.getMethodNames()

		parts = str.split(' ', 2) 
		if len(parts) != 3:
			raise ESipMessageException()	

		# check if message is request
		if parts[0].strip() in methodNames:
			# check sip version string
			sipVersion = self.parseSipVersion(parts[2])

			# parse uri 
			requestUri = self.parseUri(parts[1])

			result = SipRequest()
			result.setMethod(parts[0].strip())
			result.setRequestUri(requestUri)
			result.setSipVersion(sipVersion)

		# check if message is response 
		elif parts[1].isdigit():
			sipVersion = self.parseSipVersion(parts[0])

			result = SipResponse()
			result.setStatusCode(int(parts[1]))
			result.setReasonPhrase(parts[2].strip())
			result.setSipVersion(sipVersion)
		else:
			raise ESipMessageException()

		return result

	def parseHeader(self, str):
		headerParts = str.split(':', 1) 

		if len(headerParts) != 2:
			raise ESipMessageHeaderInvalid()

		name = headerParts[0].strip().lower()
		body = headerParts[1].strip()

		result = HeaderFactory.createHeaderFromData(name, body)

		return result	

	def parseSipVersion(self, str):
		if str != 'SIP/2.0':
			raise ESipMessageException()

		return str

	def parseUri(self, str):
		result = None
		if str.startswith('sip'):
			result = SipUri(str)
		elif str.startswith('tel'):
			result = TelUri(str)
		else:
			raise ESipMessageException

		return result

class HeaderFactory(object):
	HEADER_NAMES = {
		'authentication-info' : AuthenticationInfoHeader,
		'from' : SipFromHeader,
		'contact': ContactHeader,
		'content-type': ContentTypeHeader,
		'content-length': ContentLengthHeader,
		'call-id' : SipCallIdHeader,
		'cseq' : SipCSeqHeader,
		'to' : SipToHeader,
		'via' : SipViaHeader,
		'www-authenticate' : WwwAuthenticateHeader,
		'proxy-authenticate' : ProxyAuthenticateHeader,
		'authorization' : AuthorizationHeader}

	COMPACT_FORMS = {
		'f': 'from',
		'c': 'content-type',
		'i': 'call-id',
		'l': 'content-length',
		'm': 'contact',
		't': 'to',
		'v': 'via'}

	@staticmethod
	def createHeaderFromData(name, body):

		id = name.lower()

		if HeaderFactory.COMPACT_FORMS.has_key(name):
			id = HeaderFactory.COMPACT_FORMS[name]
		
		if (HeaderFactory.HEADER_NAMES.has_key(id)):
			result = HeaderFactory.HEADER_NAMES[id](body)
		else:
			result = Header(name, body)

		return result

	def createFromHeader(self, address, tag = None):
		"""Creates a new FromHeader based on the newly supplied address and tag values."""
		result = SipFromHeader()
		result.setAddress(address)
		if tag is not None:
			result.setTag(tag)
		return result

	def createToHeader(self, address, tag = None):
		"""Creates a new ToHeader based on the newly supplied address and tag values."""
		result = SipToHeader()
		result.setAddress(address)
		if tag is not None:
			result.setTag(tag)
		return result

###### sip messsage ############################################################

class SipMessage(object):
	def __init__(self):
		self.__headers = []
		self.__content = None
		self.__sipVersion = 'SIP/2.0'
	  
	def __str__(self):

		result = self.getFirstLine() + "\n"

		for header in self.__headers:
			result += str(header) + "\n"

		result += "\n"

		if not self.__content is None:
			result += self.__content

		return result


	def addHeader(self, header):
		self.__headers.append(header)

	def removeHeader(self, header):
		self.__headers.remove(header)

	def getHeaders(self):
		return self.__headers

	def getHeaderByType(self, type):
		result = None
		for header in self.__headers:
			if isinstance(header, type):
				result = header
		return result

	def getHeadersByType(self, type):
		result = []	
		for header in self.__headers:
			if isinstance(header, type):
				result.append(header)
		return result

	def removeHeadersByType(self, type):
		for header in self.__headers:
			if isinstance(header, type):
				self.__headers.remove(header)

	def getContent(self):
		return self.__content
	
	def setContent(self, content, contentTypeHeader = None):
		self.__content = content

		if contentTypeHeader is not None:
			self.addHeader(contentTypeHeader)

	def getSipVersion(self):
		return self.__sipVersion

	def setSipVersion(self, sipVersion):
		self.__sipVersion = sipVersion 

	def getFirstLine(self):
		return ''

	def getTopmostViaHeader(self):
		result = None
		for header in self.__headers:
			if isinstance(header, SipViaHeader):
				result = header
				break
		return result

	def getToTag(self):
		result = None
		toHeader = self.getToHeader()
		if not toHeader is None:
			result = toHeader.getTag()
		return result

	def getToHeader(self):
		result = None
		for header in self.__headers:
			if isinstance(header, SipToHeader):
				result = header
				break
		return result

	def getRouteHeaders(self):
		return []

	def getTransactionId(self):
		"""Generate (compute) a transaction ID unique for this SIP message.

		return: A string containing the concatenation of various portions of the From,To,Via and
		RequestURI portions of this message as specified in RFC 2543: All responses to a
		request contain the same values in the Call-ID, CSeq, To, and From fields (with the
		possible addition of a tag in the To field (section 10.43)). This allows responses
		to be matched with requests.

		return: A string that can be used as a transaction identifier for this message. This can be
		used for matching responses and requests (i.e. an outgoing request and its matching
		response have the same computed transaction identifier).
		"""

		topVia = self.getTopmostViaHeader()
		cSeqHeader = self.getHeaderByType(SipCSeqHeader)
		fromHeader = self.getHeaderByType(SipFromHeader)
		toHeader = self.getHeaderByType(SipToHeader)
		callIdHeader = self.getHeaderByType(SipCallIdHeader)

		# Have specified a branch Identifier so we can use it to identify
		# the transaction. BranchId is not case sensitive.
		# Branch Id prefix is not case sensitive.
		if not topVia is None and not topVia.getBranch() is None:
			# Bis 09 compatible branch assignment algorithm.
   			# implies that the branch id can be used as a transaction identifier.
			if cSeqHeader is None:
				raise ESipMessageException('CSeq header is missing')

			if cSeqHeader.getMethod() == SipRequest.METHOD_CANCEL:
			    return (topVia.getBranch() + ':' + cSeqHeader.getMethod()).lower()
			else:
			    return topVia.getBranch().lower()
		else:
			# old style client so construct the transaction identifier
			# from various fields of the request.
            		result = ''
			if fromHeader is None or toHeader is None or callIdHeader is None or cSeqHeader is None:
				raise ESipMessageException('From, To, CallId or CSeq header is missing')

			if not fromHeader.getTag() is None:
				result += fromHeader.getTag() + '-'
			if not callIdHeader is None:
				cid = callIdHeader.getCallId()
				result += cid + '-'
			result += str(cSeqHeader.getSeqNumber()) + '-' + cSeqHeader.getMethod()

			# TODO:
			#if not topVia is None:
			#	result += '-' + topVia.getSentBy().encode()
			#	if not topVia.getSentBy().hasPort():
                 	#		result += '-5060'

			if cSeqHeader.getMethod() == SipRequest.METHOD_CANCEL:
				result += SipRequest.METHOD_CANCEL
		
		return result.lower().replace(':', '-').replace('@', '-') + '-' + SipUtils.generateSignature()

	def getCallId(self):
		"""Get call id from appropriate header. Return None if header doesn't exist"""
		result = None
		callIdHeader = self.getHeaderByType(SipCallIdHeader)
		if not callIdHeader is None:
			result = callIdHeader.getCallId() 
		return result

class SipRequest(SipMessage):
	"""Sip Request"""

	# rfc3261 - confirms that client has received a final Response to an INVITE Request.
	METHOD_ACK = 'ACK'

	# rfc3261 - Indicates to the server that client wishes to release the call leg.
	METHOD_BYE = 'BYE'

	# rfc3261 - Cancels a pending User Agent Client Request.
	METHOD_CANCEL = 'CANCEL'

	# rfc3261 - Indicates that user or service is being invited to participate in a session.
	METHOD_INVITE = 'INVITE'

	# rfc3261 - Queries a server with regards to its capabilities.
	METHOD_OPTIONS = 'OPTIONS'

	# rfc3261 - Registers contact information with a SIP server. 
	METHOD_REGISTER = 'REGISTER'

	# rfc2976 - Used to carry session related control information that is generated during a session.
	# This functionality is defined in RFC2976.
	METHOD_INFO = 'INFO'

	# rfc3262 - Similiar in operation to ACK, however specific to the reliability of provisional
	# Responses. This functionality is defined in RFC3262.
	METHOD_PRACK = 'PRACK'

	# rfc3311 - Allows a client to update parameters of a session without impacting the state
	# of a dialog. This functionality is defined in RFC3311.
	METHOD_UPDATE = 'UPDATE'

	# rfc3265 - Provides an extensible framework by which SIP nodes can request notification
	# from remote nodes indicating that certain events have occurred. This functionality is defined in RFC3265.
	METHOD_SUBSCRIBE = 'SUBSCRIBE'

	# rfc3265 - Provides an extensible framework by which SIP nodes can get notification from remote nodes indicating
	# that certain events have occurred. This functionality is defined in RFC3265.
	METHOD_NOTIFY = 'NOTIFY'

	# rfc3428 - For sending instant messages using a metaphor similar to that of a two-way pager or SMS enabled
	# handset. This functionality is defined in RFC3428.
	METHOD_MESSAGE ='MESSAGE'

	# rfc3515 - requests that the recipient REFER to a resource provided in the request 
	METHOD_REFER = 'REFER'

	# rfc3903 - for publishing event state 
	METHOD_PUBLISH = 'PUBLISH'

	def __init__(self):
		SipMessage.__init__(self)
		self._method = None 
		self._requestUri = None 
		
	def getMethod(self):
		return self._method

	def setMethod(self, method):
		self._method = method

	def getRequestUri(self):
		return self._requestUri

	def setRequestUri(self, requestUri):
		self._requestUri = requestUri

	def getFirstLine(self):
		return self._method + ' ' + str(self._requestUri) + ' SIP/2.0' 

	def checkHeaders(self):
		"""Quick check if all required headers are present"""

		#requiredHeaders = [SipFromHeader, SipToHeader, SipCSeqHeader, SipCallIdHeader, MaxForwardsHeader, SipViaHeader]
		requiredHeaders = [SipFromHeader, SipToHeader, SipCSeqHeader, SipCallIdHeader, SipViaHeader]
        	# Contact (only for INVITE)
		if self._method == SipRequest.METHOD_INVITE:
			requiredHeaders.append(ContactHeader)

		for rh in requiredHeaders:
			found = False	
			for h in self.getHeaders():
				if isinstance(h, rh):
					found = True
					break;
			if not found:
				raise ESipMessageException('Missing required header: ' + rh.__name__)

class SipResponse(SipMessage):
	"""Sip Response"""

	RESPONSE_TRYING = 100
	RESPONSE_OK = 200
	RESPONSE_UNAUTHORIZED = 401
	RESPONSE_PROXY_AUTHENTICATION_REQUIRED = 407
  
	def __init__(self):
		SipMessage.__init__(self)
		self._statusCode = None 
		self._reasonPhrase = None

	def getStatusCode(self):
		return self._statusCode

	def setStatusCode(self, statusCode):
		self._statusCode = statusCode 

	def getReasonPhrase(self):
		return self._reasonPhrase

	def setReasonPhrase(self, reasonPhrase):
		self._reasonPhrase = reasonPhrase 

	def getFirstLine(self):
		return 'SIP/2.0 ' + str(self._statusCode) + ' ' + str(self._reasonPhrase)

class MessageFactory(object):

	@staticmethod
	def createRequest(requestUri = None, method = None):
		"""Creates a new Request message"""
		result = SipRequest()
		if requestUri is not None:
			result.setRequestUri(requestUri)
		if method is not None:
			result.setMethod(method)
		return result

	@staticmethod
	def createResponse(statusCode, request):
		"""Creates a new Response message of type specified by the statusCode paramater, based on a specific Request message."""
		response = SipResponse()
		response.setStatusCode(statusCode)
		response.setReasonPhrase('OK')
		for header in request.getHeaders():
 			if isinstance(header, (SipToHeader, SipFromHeader, SipCallIdHeader, SipCSeqHeader, ContactHeader, SipViaHeader)):
				response.addHeader(header)
		return response

	@staticmethod
	def createRequestRegister(user, hop):
		requestUri = SipUri('sip:%s' % user.getSipDomain())
		userUri = SipUri('sip:%s@%s' % (user.getUserName(), user.getSipDomain()))
		userSipAddress = SipAddress()
		userSipAddress.setUri(userUri)
		userSipAddress.setDisplayName(user.getDisplayName())

		result = SipRequest()
		result.setMethod(SipRequest.METHOD_REGISTER)
		result.setRequestUri(requestUri)

		fromHeader = SipFromHeader()
		fromHeader.setAddress(userSipAddress)
		fromHeader.setTag(SipUtils.generateTag())
		result.addHeader(fromHeader)
		toHeader = SipToHeader()
		toHeader.setAddress(userSipAddress)
		result.addHeader(toHeader)

		result.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier(hop.getHost())))

		result.addHeader(SipCSeqHeader('1 REGISTER'))
		viaHeader = SipViaHeader('SIP/2.0/UDP some.host')
		viaHeader.setBranch(SipUtils.generateBranchId());
		result.addHeader(viaHeader)
		result.addHeader(MaxForwardsHeader('70'))
		result.addHeader(ExpiresHeader('3600'))

		contactUri = SipUri()
		contactUri.setScheme(Uri.SCHEME_SIP)
		contactUri.setHost(hop.getHost());
		contactUri.setPort(hop.getPort());
		contactHeader = ContactHeader()
		contactHeader.setAddress(contactUri)
		result.addHeader(contactHeader);

		# create authorization header
		authorizationHeader = AuthorizationHeader()
		authorizationHeader.setScheme('Digest')
		authorizationHeader.setUserName(user.getAuthUserName())
		authorizationHeader.setRealm(user.getSipDomain())
		authorizationHeader.setUri(str(requestUri))
		authorizationHeader.setNonce('')
		authorizationHeader.setResponse('')
		result.addHeader(authorizationHeader)
		
		return result

	@staticmethod
	def createRequestDeRegister(request):
		result = copy.deepcopy(request)

		expiresHeader = result.getHeaderByType(ExpiresHeader)
		expiresHeader.setExpires(0)			

		# Increment cseq
		cSeq = result.getHeaderByType(SipCSeqHeader)
               	cSeq.setSeqNumber(cSeq.getSeqNumber() + 2)

		# remove transaction related stuff
		fromHeader = result.getHeaderByType(SipFromHeader)
		if not fromHeader is None:
			fromHeader.setTag(SipUtils.generateTag())

		topmostViaHeader = result.getTopmostViaHeader()
		if not topmostViaHeader is None:
			topmostViaHeader.setBranch(None);

		return result

	@staticmethod
	def createRequestInvite(user1, user2, hop):

		if not isinstance(user1, SipAddress) or not isinstance(user2, SipAddress):
			raise ESipMessageException("Invalid argument format")
		
		user1Uri = user1.getUri()
		user1SipAddress = SipAddress()
		user1SipAddress.setUri(user1Uri)
		user1SipAddress.setDisplayName(user1.getDisplayName())

		user2Uri = user2.getUri()
		user2SipAddress = SipAddress()
		user2SipAddress.setUri(user2Uri)
		user2SipAddress.setDisplayName(user2.getDisplayName())

		result = SipRequest()
		result.setMethod(SipRequest.METHOD_INVITE)
		result.setRequestUri(user2Uri)

		fromHeader = SipFromHeader()
		fromHeader.setAddress(user1SipAddress)
		fromHeader.setTag(SipUtils.generateTag())
		result.addHeader(fromHeader)
		toHeader = SipToHeader()
		toHeader.setAddress(user2SipAddress)
		result.addHeader(toHeader)

		result.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier(hop.getHost())))

		result.addHeader(SipCSeqHeader('1 INVITE'))
		viaHeader = SipViaHeader('SIP/2.0/UDP some.host')
		viaHeader.setBranch(SipUtils.generateBranchId());
		result.addHeader(viaHeader)
		result.addHeader(MaxForwardsHeader('70'))

		contactUri = SipUri()
		contactUri.setScheme(Uri.SCHEME_SIP)
		contactUri.setHost(hop.getHost());
		contactUri.setPort(hop.getPort());
		contactHeader = ContactHeader()
		contactHeader.setAddress(contactUri)
		result.addHeader(contactHeader);

		# create authorization header
		#authorizationHeader = AuthorizationHeader()
		#authorizationHeader.setScheme('Digest')
		#authorizationHeader.setUserName(user1.getAuthUserName())
		#authorizationHeader.setRealm(user1.getSipDomain())
		#authorizationHeader.setUri(str(user1Uri))
		#authorizationHeader.setNonce('')
		#authorizationHeader.setResponse('')
		#result.addHeader(authorizationHeader)

		result.setContent("v=0\no=UserA 2890844526 2890844526 IN IP4 anfdata.cz\ns=Session SDP\nc=IN IP4 100.101.102.103\nt=0 0\nm=audio 49170 RTP/AVP 0\na=rtpmap:0 PCMU/8000")

		result.addHeader(ContentLengthHeader(len(result.getContent())))
		result.addHeader(ContentTypeHeader("application/sdp"))
		return result

	@staticmethod
	def createRequestAck(inviteRequest):
		result = MessageFactory.createRequest(copy.deepcopy(inviteRequest.getRequestUri()), SipRequest.METHOD_ACK)

		result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipFromHeader)))
		result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipToHeader)))
		result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipCallIdHeader)))
		maxForwards = inviteRequest.getHeaderByType(MaxForwardsHeader)
		if not maxForwards is None:
			result.addHeader(copy.deepcopy(maxForwards))

		topVia = inviteRequest.getTopmostViaHeader()
		if not topVia is None:
			result.addHeader(copy.deepcopy(topVia))
			
		# change cseq method, number must stay untouched 
		cSeqHeader = copy.deepcopy(inviteRequest.getHeaderByType(SipCSeqHeader))
               	cSeqHeader.setMethod(result.getMethod())
		result.addHeader(cSeqHeader)
		return result

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):
	def setUp(self):
		self.CONTENT = 'MyContent'
		self.USR_BOB_USERNAME =  'bob'
		self.USR_BOB_DISPLAYNAME =  'Bob'
		self.USR_BOB_DOMAIN =  'beloxi.com'
		self.USR_BOB_SHORT = 'sip:%s@%s' % (self.USR_BOB_USERNAME, self.USR_BOB_DOMAIN)
		self.USR_BOB_ADDR = '"%s" <%s>' % (self.USR_BOB_DISPLAYNAME, self.USR_BOB_SHORT)

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

		user1 = SipAddress()
		user1Uri = SipUri()
		user1Uri.setScheme(Uri.SCHEME_SIP)
		user1Uri.setUser("ITSY000001")
		user1Uri.setHost("brn10.iit.ims")
		user1.setDisplayName('ITSY000001')
		user1.setUri(user1Uri)

		user2 = SipAddress()
		user2Uri = SipUri()
		user2Uri.setScheme(Uri.SCHEME_SIP)
		user2Uri.setUser("ITSY000002")
		user2Uri.setHost("brn10.iit.ims")
		user2.setDisplayName('ITSY000002')
		user2.setUri(user2Uri)

		localHop = Hop()
		localHop.setHost('127.0.0.1')
		localHop.setPort(5060)

		inv = MessageFactory.createRequestInvite(user1, user2, localHop)

		ack = MessageFactory.createRequestAck(inv)
 
	def testSipMessageParser(self):
		f = open('data/sip_options.txt', 'rb')
		msg = f.read()
		f.close()
		sipParser = SipParser()
		sipParser.parseSIPMessage(msg) 

		f = open('data/sip_invite.txt', 'rb')
		msg = f.read()
		f.close()
		sipParser = SipParser()
		sipParser.parseSIPMessage(msg) 

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


