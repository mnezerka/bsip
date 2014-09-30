
class Sip():
    '''General SIP protocol definitions'''

    # cookie that should be used as a prefix for all branch hashes
    BRANCH_MAGIC_COOKIE = 'z9hG4bK'
    
    @staticmethod
    def getMethodNames():
        result = [SipRequest.METHOD_ACK, SipRequest.METHOD_BYE, SipRequest.METHOD_CANCEL, SipRequest.METHOD_INVITE, SipRequest.METHOD_OPTIONS, SipRequest.METHOD_REGISTER,
            SipRequest.METHOD_INFO, SipRequest.METHOD_PRACK, SipRequest.METHOD_UPDATE, SipRequest.METHOD_SUBSCRIBE, SipRequest.METHOD_NOTIFY, SipRequest.METHOD_MESSAGE, SipRequest.METHOD_REFER]
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

class SipUtils():
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

