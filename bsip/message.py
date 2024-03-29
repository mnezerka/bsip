#!/usr/bin/python

import unittest
import random
import time
import copy
import re
#import urlparse

from sip import Sip
from sip import SipException
from sip import SipUtils
from sip import HttpUtils
from sip import Hop 
from sip import SipUri 
from sip import SipAddress
from user import User


############ headers ###########

class MediaType():
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
                raise SipException('Invalid format for media type header')

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

class Header():
    PARAM_ACTION = 'action';
    PARAM_ALERT = 'alert';
    PARAM_ALGORITHM = 'algorithm';
    PARAM_BRANCH = 'branch';
    PARAM_CARD = 'card';
    PARAM_CAUSE = 'cause';
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
    PARAM_NONCE = 'nonce';
    PARAM_NONCE_COUNT = 'nc';
    PARAM_NON_URGENT = 'non-urgent';
    PARAM_NORMAL = 'normal';
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
                    raise SipException("Cannot parse parameter:" + param)
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
                        raise SipException("Cannot parse parameter:" + param)
                    # remove quotes
                    value = value.replace('"', '')
                    self[key.strip()] = value.strip()

    # override method to handle quoting
    #def setParameter(self, name, value):
    # Parameters.setParameter(self, name, value)
    
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
        return self.get(Header.PARAM_NC) if Header.PARAM_NC in self else 0

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
            raise SipException('Authorization scheme is mandatory')
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
    nc           - The nonce count value transmitted by clients if a qop-header is also transmitted.
                         HTTP digest auth only.
    nonce        - The nonce the server sent for digest auth, sent back by the client. A nonce should be
                         unique for every 401 response for HTTP digest auth.
    opaque   - The opaque header from the server returned unchanged by the client. It is recommended
                         that this string be base64 or hexadecimal data. Digest auth only.
    password - When the authentication type is basic this is the password transmitted by the client, else None.
    qop          - Indicates what "quality of protection" the client has applied to the message for HTTP digest auth.
    realm        - This is the server realm sent back for HTTP digest auth.
    response - A string of 32 hex digits computed as defined in RFC 2617, which proves that the user knows
                         a password. Digest auth only.
    uri          - The URI from Request-URI of the Request-Line; duplicated because proxies are allowed to change
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
                        raise SipException()
                    self[key.strip()] = value.strip()

    def getAddress(self):
        return self.__address

    def setAddress(self, address):
        assert isinstance(address, SipAddress)
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

    def __str__(self):
        a = self.getAddress()
        if a is None:
            raise SipException('Empty address in Contact header')

        result = str(self.getName()) + ': '
        if a.getDisplayName() is None:
            result += '<' + str(a.getUri()) + '>'
        else:
            result += '"' + a.getDisplayName() + '" <' + str(a.getUri()) + '>'
        return result

class ContentLengthHeader(Header):
    def __init__(self, body = None):
        Header.__init__(self, 'Content-Length' , body)
        self._contentLength = 0 
        if body is not None:
            if isinstance(body, int):
                self._contentLength = body
            elif body.isdigit():
                self._contentLength = int(body)
            else:
                raise SipException("Invalid header body for Content-length header")

    def getContentLength(self):
        return self._contentLength

    def setContentLength(self, val):
        self._contentLength = val

class ContentTypeHeader(Header, MediaType):
    def __init__(self, body = None):
        Header.__init__(self, 'Content-Type' , body)
        MediaType.__init__(self, body)

    def __str__(self):
        result = self.getName() + ': ' + MediaType.__str__(self)
        return result

class ExpiresHeader(Header):
    """The Expires header field gives the relative time after which the message (or content) expires."""
    
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
                raise SipException('Invalid format for CSeq header')

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

class SipRecordRouteHeader(SipAddressHeader):
    def __init__(self, body = None):
        SipAddressHeader.__init__(self, 'Record-Route' , body)

class SipRouteHeader(SipAddressHeader):
    def __init__(self, body = None):
        SipAddressHeader.__init__(self, 'Route' , body)

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
        self[SipViaHeader.PARAM_PROTOCOL] = 'SIP/2.0/' 

        if body is not None:
            (address, sep, parameters) = body.partition(';')
            if len(address) == 0:
                raise SipException()
            if len(sep) == 0:
                parameters = None
            
            # get transport and parameters
            (beg, sep, host) = address.partition(' ') 
            
            if not beg.startswith('SIP/2.0/') or len(sep) == 0:
                raise SipException()

            # get transport protocol 
            transport = beg[len('SIP/2.0/'):] 
            if transport.lower() not in [Sip.TRANSPORT_UDP, Sip.TRANSPORT_TCP, Sip.TRANSPORT_SCTP]:
                raise SipException()

            self[SipViaHeader.PARAM_TRANSPORT] = transport 
    
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
                        raise SipException()
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
        """Returns the value of the protocol used. e.g. SIP/2.0"""
        return self[SipViaHeader.PARAM_PROTOCOL] if SipViaHeader.PARAM_PROTOCOL in self else None

    def setProtocol(self, protocol):
        """Sets the value of the protocol parameter. e.g. e.g. SIP/2.0"""
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
        """Returns the value of the transport network protocol, e.g. tcp, udp, sctp"""
        return self[Header.PARAM_TRANSPORT] if Header.PARAM_TRANSPORT in self else None

    def setTransport(self, transport):
        """Sets the value of the transport, e.g. tcp, udp, sctp"""
        self[Header.PARAM_TRANSPORT] = transport

    def getTTL(self):
        """Returns the value of the ttl parameter, or -1 if this is not set."""
        return self.getParameter(SipViaHeader.PARAM_TTL)

    def setTTL(self, ttl):
        """Sets the value of the ttl parameter."""
        self.setParameter(SipViaHeader.TTL, ttl)

    def __str__(self):
        result = self.getName() + ': '
        result += self.getProtocol().upper() + self.getTransport().upper() + ' '
        result += self.getHost() 
        if self.getPort() is not None:
            result += ':' + str(self.getPort())

        # other parameters
        for paramName in self.keys():
            # skip parameters used in address
            if paramName in [SipViaHeader.PARAM_HOST, SipViaHeader.PARAM_PORT, SipViaHeader.PARAM_PROTOCOL, SipViaHeader.PARAM_TRANSPORT]:
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
    domain      - list of URIs that define the protection space. If a URI is an absolute path,
                            it is relative to the canonical root URL of the server being accessed.
    nonce           - A server-specified data string which should be uniquely generated each time
                            a 401 response is made. It is recommended that this string be base64 or hexadecimal data.
    opaque      - A string of data, specified by the server, which should be returned by the client
                            unchanged in the Authorization header of subsequent requests with URIs in the same
                protection space. It is recommended that this string be base64 or hexadecimal data.
    qop             - A set of quality-of-privacy directives such as auth and auth-int.
    realm           - A string to be displayed to users so they know which username and password to use.
                            This string should contain at least the name of the host performing the authentication
                and might additionally indicate the collection of users who might have access.
    type            - The type of the auth mechanism. HTTP currently specifies Basic and Digest.

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

######## messages ################

class SipMessage():
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
                break
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

    def getTopViaHeader(self):
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

    def setToTag(self, tag):
        toHeader = self.getToHeader()
        if not toHeader is None:
            result = toHeader.setTag(tag)

    def getToHeader(self):
        result = None
        for header in self.__headers:
            if isinstance(header, SipToHeader):
                result = header
                break
        return result

    def getFromHeader(self):
        result = None
        for header in self.__headers:
            if isinstance(header, SipFromHeader):
                result = header
                break
        return result

    def getFromTag(self):
        result = None
        fromHeader = self.getFromHeader()
        if not fromHeader is None:
            result = fromHeader.getTag()
        return result

    def getRouteHeaders(self):
        return []

    def getTransactionId(self):
        """Generate (compute) a transaction ID unique for this SIP message."""

        topVia = self.getTopViaHeader()
        cSeqHeader = self.getHeaderByType(SipCSeqHeader)

        # Have specified a branch Identifier so we can use it to identify
        # the transaction. BranchId is not case sensitive.
        # Branch Id prefix is not case sensitive.
        if topVia is None:
            raise SipException('Missing top Via header')

        if topVia.getBranch() is None:
            raise SipException('Missing branch in top Via header')

        if cSeqHeader is None:
            raise SipException('CSeq header is missing')

        if cSeqHeader.getMethod() == Sip.METHOD_CANCEL:
            return (topVia.getBranch() + ':' + cSeqHeader.getMethod()).lower()
        else:
            return topVia.getBranch().lower()

    def getDialogId(self, isServerTransaction):
        '''Get A dialog identifier constructed from this messsage.

        This is an id that can be used to identify dialogs.
        '''
        fromTag = self.getFromTag()
        if fromTag is None:
            return None
        toTag = self.getToTag()
        if toTag is None:
            return None
        callId= self.getCallId()
        if callId is None:
            return None

        result = callId
        if isServerTransaction:
                result += ":%s:%s" %(toTag, fromTag)
        else:
                result += ":%s:%s" %(fromTag, toTag)

        return result.lower()

    def getCallId(self):
        """Get call id from appropriate header. Return None if header doesn't exist"""
        result = None
        callIdHeader = self.getHeaderByType(SipCallIdHeader)
        if not callIdHeader is None:
            result = callIdHeader.getCallId() 
        return result

    def setCallId(self, callId):
        """Set call id in appropriate header. Raise exception if header doesn't exist"""
        callIdHeader = self.getHeaderByType(SipCallIdHeader)
        if callIdHeader is None:
            raise SipException('Call-ID header is missing')
        callIdHeader.setCallId(callId) 

    def incCSeq(self):
        """Increments CSeq header by one. Raise exception if header doesn't exist"""
        hdr = self.getHeaderByType(SipCSeqHeader)
        if hdr is None:
            raise SipException('CSeq header is missing')
        hdr.setSeqNumber(hdr.getSeqNumber() + 1)

class SipRequest(SipMessage):
    """Sip Request"""


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
        if self._method == Sip.METHOD_INVITE:
            requiredHeaders.append(ContactHeader)

        for rh in requiredHeaders:
            found = False 
            for h in self.getHeaders():
                if isinstance(h, rh):
                    found = True
                    break;
            if not found:
                raise SipException('Missing required header: ' + rh.__name__)

class SipResponse(SipMessage):
    """Sip Response"""

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

######## parser ################

class SipParser():
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
    
    def parseSIPMessage(self, dataBuffer):
        '''Parse sip message from the data buffer represented as bytes object
        
        Headers are interpreted as UTF-8 encoded text data, body is sequence of bytes 
        '''

        if dataBuffer is None:
            raise SipException()

        # locate a body
        msgBody = None
        for bodySeparator in (b"\r\n\r\n", b"\r\r", b"\n\n"):
            bodyOffset = dataBuffer.find(bodySeparator)
            if bodyOffset != -1:
                msgBody = dataBuffer[bodyOffset + len(bodySeparator):]
                dataBuffer = dataBuffer[:bodyOffset]
                break
        if msgBody is None:
            raise SipException()

        # split message into lines and put aside start line
        lines = dataBuffer.decode('UTF-8').splitlines()

        if len(lines) < 2:
            raise SipException("Not enough header lines in message")

        # parse first line and get instance of request or response object
        msg = self.parseFirstLine(lines[0]) 

        # parse headers
        headersData = []
        for line in lines[1:]:
            # end on first empty line 
            if len(line) == 0:
                break

            # process folded headers (split into more lines)
            if line[0] in (' ', '\t'):
                if len(headersData) == 0:
                    raise SipException('Invalid whitespace characters found while parsing headers') 
                lastHeaderData = headersData.pop() 
                lastHeaderData[1] += ' ' + line.strip()
                continue 
            
            headerParts = re.search('([^:]+) *:([ \t]*)(.+)', line)
            if headerParts is None:
                raise SipException('Bad header: %s' % line)
            headerName = headerParts.group(1)
            headerValIndent = headerParts.group(2)
            headerValue = headerParts.group(3)

            # convert 2nd type of multiline headers into one-line header
            # h1: xxx
            # h1:  yyy
            # should be parsed as h1: xxx yyy
            if len(headersData) > 0:
                # get previous header
                lastHeaderDataIx = len(headersData) - 1
                lastHeaderData = headersData[lastHeaderDataIx]
                # if header name matches and indent of this header is greater than prvious 
                if lastHeaderData[0] == headerName and len(lastHeaderData[2]) < len(headerValIndent):
                    headersData[lastHeaderDataIx][1] += ', ' + headerValue.strip() 
                    #print headersData[lastHeaderDataIx][1] 
                    continue

            headersData.append([headerName, headerValue, headerValIndent])

        #for hd in headersData:
        #    print hd

        # parse individual headers
        contentLengthHeader = None
        for headerData in headersData:
            headers = self.parseHeader(headerData[0], headerData[1])
            #print headers
            for header in headers:
                if isinstance(header, ContentLengthHeader):
                    contentLengthHeader = header
                msg.addHeader(header)

        if contentLengthHeader is not None:
            contentLength = contentLengthHeader.getContentLength()  
            if contentLength != len(msgBody):
                raise SipException("Body length differs from value of Content-length header")
        elif msgBody is not None:
            if len(msgBody) > 0:
                raise SipException("Body without Content-length header found.")

        msg.setContent(msgBody)

        return msg

    def parseFirstLine(self, str):
        result = None

        methodNames = Sip.getMethodNames()

        parts = str.split(' ', 2) 
        if len(parts) != 3:
            raise SipException()    

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
            raise SipException()

        return result

    def parseHeader(self, headerName, headerValues):
        result = []
        headerValues = headerValues.strip()
        # check for multiple header values (comma separated). This is not allowed for some headers
        # since their grammar doesn't follow form listed in SIP RFC 7.3
        if headerName.lower() in ['www-authenticate', 'authorization', 'proxy-authenticate', 'proxy-Authorization']: 
            headerValuesParts = [headerValues]
        else:
            headerValuesParts = re.split(r"[^\\],", headerValues) 
        for headerValue in headerValuesParts:
            result.append(HeaderFactory.createHeaderFromData(headerName, headerValue))

        return result 

    def parseSipVersion(self, str):
        if str != 'SIP/2.0':
            raise SipException()

        return str

    def parseUri(self, str):
        result = None
        if str.startswith('sip'):
            result = SipUri(str)
        elif str.startswith('tel'):
            result = TelUri(str)
        else:
            raise SipException

        return result

######## factories ################

class AddressFactory():
    @staticmethod
    def createUri(str):
        result = None
        if str.startswith('sip'):
            result = SipUri(str)
        elif str.startswith('tel'):
            result = TelUri(str)
        else:
            result = Uri(str)

        return result

class HeaderFactory():
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

        if name in HeaderFactory.COMPACT_FORMS:
            id = HeaderFactory.COMPACT_FORMS[name]
        
        if id in HeaderFactory.HEADER_NAMES:
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

    @staticmethod
    def createRouteFromRecordRoute(recordRouteHeader):
        '''Creates RouteHeader from RecordRouteHeader (deep copy)'''
        result = SipRouteHeader()
        result.setAddress(copy.deepcopy(recordRouteHeader.getAddress()))
        for param in recordRouteHeader:
            result[param] = recordRouteHeader.get(param)

        return result

class MessageFactory():
    """Factory for SIP messages (requests and responses)"""

    @staticmethod
    def duplicateMessage(msg):
        return copy.deepcopy(msg)

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
    def createRequestRegister(user):
        assert isinstance(user, SipAddress)

        requestUri = SipUri('sip:%s' % user.getUri().getHost())

        result = SipRequest()
        result.setMethod(Sip.METHOD_REGISTER)
        result.setRequestUri(requestUri)

        fromHeader = SipFromHeader()
        fromHeader.setAddress(user)
        fromHeader.setTag(SipUtils.generateTag())

        result.addHeader(fromHeader)
        toHeader = SipToHeader()
        toHeader.setAddress(user)
        result.addHeader(toHeader)

        result.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier()))

        result.addHeader(SipCSeqHeader('1 REGISTER'))
        result.addHeader(MaxForwardsHeader('70'))
        result.addHeader(ExpiresHeader('3600'))

        contentLengthHeader = ContentLengthHeader(0)
        result.addHeader(contentLengthHeader);
        
        return result

    @staticmethod
    def createRequestInvite(user, calledAddress):
        assert isinstance(user, User)
        assert isinstance(calledAddress, SipAddress)
        
        result = SipRequest()
        result.setMethod(Sip.METHOD_INVITE)
        result.setRequestUri(calledAddress.getUri())

        fromHeader = SipFromHeader()
        fromHeader.setAddress(user.getAddress())
        fromHeader.setTag(SipUtils.generateTag())
        result.addHeader(fromHeader)

        toHeader = SipToHeader()
        toHeader.setAddress(calledAddress)
        result.addHeader(toHeader)

        result.addHeader(SipCallIdHeader(SipUtils.generateCallIdentifier()))

        result.addHeader(SipCSeqHeader('1 INVITE'))
        viaHeader = SipViaHeader('SIP/2.0/UDP some.host')
        viaHeader.setBranch(SipUtils.generateBranchId());
        result.addHeader(viaHeader)
        result.addHeader(MaxForwardsHeader('70'))
      
        result.setContent("v=0\no=UserA 2890844526 2890844526 IN IP4 anfdata.cz\ns=Session SDP\nc=IN IP4 100.101.102.103\nt=0 0\nm=audio 49170 RTP/AVP 0\na=rtpmap:0 PCMU/8000")

        result.addHeader(ContentLengthHeader(len(result.getContent())))
        result.addHeader(ContentTypeHeader("application/sdp"))
        return result

    @staticmethod
    def createRequestAck(inviteRequest):
        result = MessageFactory.createRequest(copy.deepcopy(inviteRequest.getRequestUri()), Sip.METHOD_ACK)

        result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipFromHeader)))
        result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipToHeader)))
        result.addHeader(copy.deepcopy(inviteRequest.getHeaderByType(SipCallIdHeader)))
        maxForwards = inviteRequest.getHeaderByType(MaxForwardsHeader)
        if not maxForwards is None:
            result.addHeader(copy.deepcopy(maxForwards))

        topVia = inviteRequest.getTopViaHeader()
        if not topVia is None:
            result.addHeader(copy.deepcopy(topVia))
            
        # change cseq method, number must stay untouched 
        cSeqHeader = copy.deepcopy(inviteRequest.getHeaderByType(SipCSeqHeader))
        cSeqHeader.setMethod(result.getMethod())
        result.addHeader(cSeqHeader)
        return result

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):
    """Unit tests for message classes""" 

    def setUp(self):
        self.CONTENT = 'MyContent'

        self.USR_BOB_USERNAME =  'bob'
        self.USR_BOB_DISPLAYNAME =  'Bob'
        self.USR_BOB_DOMAIN =  'beloxi.com'
        self.USR_BOB_SHORT = 'sip:%s@%s' % (self.USR_BOB_USERNAME, self.USR_BOB_DOMAIN)
        self.USR_BOB_ADDR = '"%s" <%s>' % (self.USR_BOB_DISPLAYNAME, self.USR_BOB_SHORT)

        self.USR_ALICE_USERNAME =  'alice'
        self.USR_ALICE_DISPLAYNAME =  'Alice'
        self.USR_ALICE_DOMAIN =  'atlanta.com'
        self.USR_ALICE_SHORT = 'sip:%s@%s' % (self.USR_ALICE_USERNAME, self.USR_ALICE_DOMAIN)
        self.USR_ALICE_ADDR = '"%s" <%s>' % (self.USR_ALICE_DISPLAYNAME, self.USR_ALICE_SHORT)

        a = SipAddress('%s <sip: %s@%s>' % (self.USR_BOB_DISPLAYNAME, self.USR_BOB_USERNAME, self.USR_BOB_DOMAIN))
        self.bob = User()
        self.bob.setAddress(a)

        a = SipAddress('%s <sip: %s@%s>' % (self.USR_ALICE_DISPLAYNAME, self.USR_ALICE_USERNAME, self.USR_ALICE_DOMAIN))
        self.alice = User()
        self.alice.setAddress(a)

        self.localHop = Hop()
        self.localHop.setHost('127.0.0.1')
        self.localHop.setPort(5060)


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
        tv = SipViaHeader('SIP/2.0/UDP some.host;branch=z9hG4bKsomebranch')
        m.addHeader(tv)
        cseq = SipCSeqHeader('34 REGISTER')
        m.addHeader(cseq)
        m.setContent(self.CONTENT)

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

    def testContactHeader(self):
        h = ContactHeader()
        self.assertRaises(SipException, str, h)
        h.setAddress(self.bob.getAddress())
        self.assertEqual(str(h), 'Contact: ' + self.USR_BOB_ADDR)

        h.getAddress().setDisplayName(None)
        self.assertEqual(str(h), 'Contact: <' + self.USR_BOB_SHORT + '>')

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

    def testMessageFactory(self):
        inv = MessageFactory.createRequestInvite(self.bob, self.alice.getAddress())
        ack = MessageFactory.createRequestAck(inv)

    def testHeaderFactory(self):
        rrh = SipRecordRouteHeader();
        rrh.setAddress(self.bob.getAddress())
        rrh["x"] = "val1"
        rrh["y"] = "val2"
        rh = HeaderFactory.createRouteFromRecordRoute(rrh)
        self.assertEqual(rrh.getAddress().getDisplayName(), rh.getAddress().getDisplayName())
        self.assertEqual(rrh["x"], rh["x"])
        self.assertEqual(rrh["y"], rh["y"])

    def testSipMessageDialogId(self):
        msg = MessageFactory.createRequestInvite(self.bob, self.alice.getAddress())
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
        headers = sipParser.parseHeader('Contact', "\"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>;q=0.7; expires=3600, \"Mr. Wa\,t\:s\=on\" <sip:watson@bell-telephone.com> ;q=0.1")
        self.assertEqual(len(headers), 2)
        self.assertEqual(headers[0].getAddress().getDisplayName(), "Mr. Watson")
        self.assertEqual(headers[0].getAddress().getUri().getUser(), "watson")
        self.assertEqual(headers[0].getAddress().getUri().getHost(), "worcester.bell-telephone.com")
        self.assertEqual(headers[1].getAddress().getDisplayName(), "Mr. Wa\,t\:s\=on")
        self.assertEqual(headers[1].getAddress().getUri().getUser(), "watson")
        self.assertEqual(headers[1].getAddress().getUri().getHost(), "bell-telephone.com")

    def testSipMessageParserOptions(self):
        f = open('../data/sip_options.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

    def testSipMessageParserInvite(self):
        f = open('../data/sip_invite.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

    def testSipMessageParser403Forbidden(self):
        f = open('../data/sip_register_403_forbidden.txt', 'rb')
        msg = f.read()
        f.close()
        sipParser = SipParser()
        sipParser.parseSIPMessage(msg) 

    def testSipMessageParser401Unauthorized(self):
        f = open('../data/sip_register_401.txt', 'rb')
        rawData = f.read()
        f.close()
        sipParser = SipParser()
        msg = sipParser.parseSIPMessage(rawData) 
        authHeaders = msg.getHeadersByType(AuthenticationHeader)
        self.assertEquals(len(authHeaders), 1)
        authHeader = authHeaders[0]

def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


