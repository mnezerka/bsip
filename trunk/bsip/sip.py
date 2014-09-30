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
    def testSipUtils(self):
        SipUtils.generateCallIdentifier()
        SipUtils.generateTag()
        SipUtils.generateBranchId()
       
def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


