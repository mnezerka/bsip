import hashlib
from xml.dom import minidom
import unittest
import sipmessage

class AccountManager(object):

	def __init__(self):
		self._users = []
		pass

	def getUserByUri(self, uri):
		for u in self._users:
			if u.getUri().getUser() == uri.getUser() and u.getUri().getHost() == uri.getHost():
				return u

	def add(self, user, default = False):
		self._users.append(user)
		if default:
			self.setDefaultUser(user)

	def setDefaultUser(self, user):
		self._defaultUser = user

	def getDefaultUser(self):
		return self._defaultUser

	def loadFromXmlString(self, str):
		try:
				xmlDoc = minidom.parseString(str)
		except Exception:
				print("Error: processing xml string failed")
				raise
		self._parseFromXmlDoc(xmlDoc)		

	def loadFromXml(self, filePath):
		try:
				xmlDoc = minidom.parse(filePath)
		except Exception:
				print("Error: processing (parsing) config xml file failed:", filePath)
				raise
		self._parseFromXmlDoc(xmlDoc)		

	def _parseFromXmlDoc(self, xmlDoc):

		# we are interested in bflow sections
		accounts = xmlDoc.getElementsByTagName("accounts")
		for accountNode in accounts:
			# look for thread profiles (default must be found first)
			for accountEl in accountNode.childNodes:
				if accountEl.nodeType == accountEl.ELEMENT_NODE and accountEl.tagName.lower() == "account":
					user = User()
					userAddr = sipmessage.SipAddress()	
					user.setAddress(userAddr)
					for userEl in accountEl.childNodes:
						if userEl.nodeType != accountEl.ELEMENT_NODE:
							continue
						if userEl.tagName.lower() == "sip-uri":
							uri = sipmessage.AddressFactory.createUri(_xmlNodeGetText(userEl))
							userAddr.setUri(uri)
						if userEl.tagName.lower() == "display-name":
							userAddr.setDisplayName(_xmlNodeGetText(userEl))
						if userEl.tagName.lower() == "digest-user":
							user.setDigestUser(_xmlNodeGetText(userEl))
						if userEl.tagName.lower() == "digest-password":
							user.setDigestPassword(_xmlNodeGetText(userEl))
						if userEl.tagName.lower() == "net-addr":
							userHop = sipmessage.Hop(_xmlNodeGetText(userEl))
							userHop.setTransport(sipmessage.Sip.TRANSPORT_UDP)
							user.setHop(userHop)

					if not user.getUri() is None:
						self.add(user)
class User(object):

	def __init__(self):
		self._address = None
		self._hop = None
		self._digestUserName = None
		self._digestPassword = None

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

def _xmlNodeGetText(node):
	rc = []
	for node in node.childNodes:
		if node.nodeType == node.TEXT_NODE:
			rc.append(node.data)
	return ''.join(rc)

##### unit test cases #########################################################################

class UnitTestCase(unittest.TestCase):

	def testUser(self):
		u = User()
		#u.getUri().setUser('x')
		#u.getAddress().setDisplayName('x')
		#u.getUri().setSipDomain('x')
		#u.setAuthUserName('x')
		#u.setAuthPassword('x')
		#u.getHashUserDomainPassword()

	def testAccountManager(self):
		src  = "<accounts>"
		src += "	<account>"
		src += "		<sip-uri>sip:blue@blue.domain.net</sip-uri>"
		src += "		<display-name>Blue</display-name>"
		src += "		<net-addr>1.1.1.1:60001</net-addr>"
		src += "		<digest-user>blues</digest-user>"
		src += "		<digest-password>bluep</digest-password>"
		src += "	</account>"
		src += "	<account>"
		src += "		<sip-uri>sip:green@green.domain.net</sip-uri>"
		src += "		<display-name>Green</display-name>"
		src += "		<net-addr>1.1.1.2:60002</net-addr>"
		src += "		<digest-user>greens</digest-user>"
		src += "		<digest-password>greenp</digest-password>"
		src += "	</account>"
		src += "</accounts>"

		a = AccountManager()
		a.loadFromXmlString(src)

		u = a.getUserByUri(sipmessage.SipUri("sip:blue@blue.domain.net"))
		self.assertNotEqual(u, None)
		self.assertEqual(u.getUri().getUser(), "blue")
		self.assertEqual(u.getUri().getHost(), "blue.domain.net")
		self.assertEqual(u.getAddress().getDisplayName(), "Blue")
		self.assertEqual(u.getDigestUser(), "blues")
		self.assertEqual(u.getDigestPassword(), "bluep")
		self.assertEqual(u.getHop().getHost(), "1.1.1.1")
		self.assertEqual(u.getHop().getPort(), 60001)

def suite():
	suite = unittest.TestLoader().loadTestsFromTestCase(UnitTestCase)
	return suite

if __name__ == '__main__':
	unittest.TextTestRunner(verbosity=2).run(suite())



