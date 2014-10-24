import unittest
import random
import time

class Sip():
    '''General SIP protocol definitions'''

    # cookie that should be used as a prefix for all branch hashes
    BRANCH_MAGIC_COOKIE = 'z9hG4bK'
    
    @staticmethod
    def getMethodNames():
        result = [Sip.METHOD_ACK, Sip.METHOD_BYE, Sip.METHOD_CANCEL, Sip.METHOD_INVITE, Sip.METHOD_OPTIONS, Sip.METHOD_REGISTER,
            Sip.METHOD_INFO, Sip.METHOD_PRACK, Sip.METHOD_UPDATE, Sip.METHOD_SUBSCRIBE, Sip.METHOD_NOTIFY, Sip.METHOD_MESSAGE, Sip.METHOD_REFER]
        return result

    TRANSPORT_UDP = 'udp'
    TRANSPORT_TCP = 'tcp'
    TRANSPORT_SCTP = 'sctp'

    URI_PREFIX_SIP = 'sip'
    URI_PREFIX_SIPS = 'sips'

    @staticmethod
    def getUriPrefixes():
        return [Sip.URI_PREFIX_SIP, Sip.URI_PREFIX_SIPS] 
    
    RESPONSE_TRYING = 100
    RESPONSE_OK = 200
    RESPONSE_UNAUTHORIZED = 401
    RESPONSE_PROXY_AUTHENTICATION_REQUIRED = 407

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

    RESPONSE_TRYING = 100
    RESPONSE_OK = 200
    RESPONSE_UNAUTHORIZED = 401
    RESPONSE_PROXY_AUTHENTICATION_REQUIRED = 407

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
                    str = str[len(px) + 1:].strip()
                    break 
            if self.getScheme() is None:
                raise SipException('Unsupported uri scheme')

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
                        raise SipException('Invalid parameter')
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
            raise SipException('uri attributes (scheme, host) not complete')

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

class SipAddress():
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
        self._displayName = None
        self._uri = None

        if str is not None:

            parts = str.strip().split('<', 1)
            
            # if display name is present
            if len(parts) > 1:
                # display name cannot be empty
                if len(parts[0]) > 0:
                    # remove "bad" characters from display name
                    self._displayName = parts[0].replace('"', '').strip()
                    userAddr = parts[1]
                else:
                    userAddr = parts[1]
            else:
                userAddr = parts[0]

            if userAddr.find('>') != -1:
                userAddr = userAddr[:userAddr.find('>')] 

            if userAddr.startswith('sip'):
                self._uri = SipUri(userAddr)
            elif userAddr.startswith('tel'):
                self._uri = TelUri(userAddr)
            else:
                raise SipException("Invalid address %s" % userAddr)

    def getDisplayName(self):
        """Gets the display name of this Address, or null if the attribute is not set."""
        return self._displayName

    def setDisplayName(self, displayName):
        """Sets the display name of the Address."""
        self._displayName = displayName

    def getUri(self):
        """Returns the URI of this Address."""
        return self._uri

    def setUri(self, uri):
        """Sets the URI of this Address."""
        self._uri = uri

    def isWildcard(self):
        """This determines if this address is a wildcard address."""
        pass

    def __str__(self):
        if self._displayName is None:
            result = str(self._uri)
        else:
            result = '"' + self._displayName + '" <' + str(self._uri) + '>'
        return result

class Hop():
    """Network address (host, port, transport) in format host[:port][;transport=udp|tcp]"""
    def __init__(self, addr = None, transport = None):
        self._host = None
        self._port = None
        self._transport = transport
        if not addr is None:
            self.parse(addr)

    def parse(self, addr):
        if type(addr) is tuple:
            (self._host, self._port) = addr 
        elif not addr is None:
            parts = addr.split(':', 1)
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
        result = self._host if not self._host is None else "None"

        if not self._port is None:
            result += ':' + str(self._port)
        if not self._transport is None:
            result += ';transport=' + self._transport

        return result

class SipUtils():
    DIGEST_POOL_SIZE = 20

    @staticmethod
    def generateCallIdentifier():
        """Generate a call identifier. This is useful when we want to generate a
         call identifier in advance of generating a message."""

        rndNumber = random.random() * 1000
        timeStamp = (time.time() % 10) * 100
        result = "%d%d" % (rndNumber, timeStamp)

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

class SipException(Exception):
    pass

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):

    def setUp(self):
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

        x = SipUri('sip: user@domain')
        self.assertEqual(x.getUser(), 'user')
        self.assertEqual(x.getHost(), 'domain')

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

        a = SipAddress('name <sip: user@domain>')
        self.assertEqual(a.getDisplayName(), 'name')
        self.assertEqual(a.getUri().getUser(), 'user')
        self.assertEqual(a.getUri().getHost(), 'domain')

    def testSipUtils(self):
        SipUtils.generateCallIdentifier()
        SipUtils.generateTag()
        SipUtils.generateBranchId()

    def testHop(self):
        IP = "1.1.1.1"
        h = Hop()
        h = Hop("1.1.1.1")
        self.assertEqual(h.getHost(), IP)
        h = Hop("1.1.1.1:89")
        self.assertEqual(h.getHost(), IP)
        self.assertEqual(h.getPort(), 89)
        h = Hop(("1.1.1.1", 89))
        self.assertEqual(h.getHost(), IP)
        self.assertEqual(h.getPort(), 89)
        h.setTransport("udp")
        self.assertEqual(h.getTransport(), "udp")
       
def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


