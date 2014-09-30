import unittest

class User():
    def __init__(self):
        self._address = None
        self._hop = None
        self._digestUserName = None
        self._digestPassword = None
        self._proxy = None

    def __str__(self):
        return str(self._address)

    def setAddress(self, address):
        self._address = address

    def getAddress(self):
        return self._address

    def setUri(self, uri):
        self._address.setUri(uri)

    def getUri(self):
        return self._address.getUri() if not self._address is None else None

    def setHop(self, hop):
        self._hop = hop

    def getHop(self):
        return self._hop    

    def getDigestUser(self):
        """Returns the name of the user that these credentials relate to."""
        return self._digestUser

    def setDigestUser(self, name):
        self._digestUser = name 

    def getDigestPassword(self):
        """Returns a password associated with this set of credentials."""
        return self._digestPassword

    def setDigestPassword(self, password):
        self._digestPassword = password

    def getDigestHash(self):
        """Get the MD5(userName:sipdomain:password)"""
        p = self._digestUser + ':' + self._address.getUri().getHost() + ':' + self._digestPassword
        m = hashlib.md5()
        m.update(p)
        return m.hexdigest()

    def setProxy(self, proxy):
        self.proxy = proxy

    def getProxy(self):
        return self.proxy

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):
    
    def testSipUtils(self):
        pass
       
def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())


