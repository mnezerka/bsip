import unittest
import hashlib
import sip 

class User():
    def __init__(self):
        self._address = None
        self._hop = None
        self._digestUserName = None
        self._digestPassword = None
        self._proxyAddr = None
        self._netAddr = None

    def __str__(self):
        return str(self._address)

    def setAddress(self, address):
        assert isinstance(address, sip.SipAddress)
        self._address = address

    def getAddress(self):
        return self._address

    def setUri(self, uri):
        assert isinstance(uri, sip.Uri)
        self._address.setUri(uri)

    def getUri(self):
        return self._address.getUri() if not self._address is None else None

    def setNetAddr(self, hop):
        assert isinstance(hop, sip.Hop)
        self._netAddr = hop

    def getNetAddr(self):
        return self._netAddr   

    def setProxyAddr(self, hop):
        assert isinstance(hop, sip.Hop)
        self._proxyAddr = hop

    def getProxyAddr(self):
        return self._proxyAddr   

    def getDigestUser(self):
        """Returns the name of the user that these credentials relate to."""
        return self._digestUserName

    def setDigestUser(self, name):
        self._digestUserName = str(name) 

    def getDigestPassword(self):
        """Returns a password associated with this set of credentials."""
        return self._digestPassword

    def setDigestPassword(self, password):
        self._digestPassword = str(password)

    def getDigestHash(self):
        """Get the MD5(userName:sipdomain:password)"""
        p = self._digestUserName + ':' + self._address.getUri().getHost() + ':' + self._digestPassword
        m = hashlib.md5()
        m.update(p)
        return m.hexdigest()

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):
    def testSipUtils(self):
        pass
       
def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


