import hashlib

class AccountManager(object):
	
	def __init__(self):
		self._users = dict()
		pass

	def getUserByUserName(self, username):
		if username in self._users:
			return self._users[username]

	def add(self, user, default = False):
		self._users[user.getUserName()] = user
		if default:
			self.setDefaultUser(user)

	def setDefaultUser(self, user):
		self._defaultUser = user

	def getDefaultUser(self):
		return self._defaultUser

class User(object):

	def __init__(self):
		self._userName = None
		self._displayName = None
		self._sipDomain = None
		self._authUserName = None
		self._authPassword = None

	def getUserName(self):
		"""Returns the name of the user that these credentials relate to."""
  		return self._userName 

	def setUserName(self, userName):
		self._userName = userName

	def getDisplayName(self):
		"""Returns the name of the user that these credentials relate to."""
  		return self._displayName 

	def setDisplayName(self, name):
		self._displayName = name 

	def getAuthUserName(self):
		"""Returns the name of the user that these credentials relate to."""
  		return self._authUserName 

	def setAuthUserName(self, name):
		self._authUserName = name 


	def getAuthPassword(self):
		"""Returns a password associated with this set of credentials."""
  		return self._authPassword

	def setAuthPassword(self, password):
		self._authPassword = password
   
	def getSipDomain(self):
		"""Returns the SIP Domain for this username password combination."""
  		return self._sipDomain

	def setSipDomain(self, sipDomain):
		self._sipDomain = sipDomain

	def getHashUserDomainPassword(self):
		"""Get the MD5(userName:sipdomain:password)"""
		p = self._authUserName + ':' + self._sipDomain + ':' + self._authPassword
		m = hashlib.md5()
		m.update(p)
		return m.hexdigest()

