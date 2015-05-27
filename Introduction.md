# References #

Sip
  * [RFC3261](http://tools.ietf.org/html/rfc3261) - SIP: Session Initiation Protocol
  * [RFC3327](http://tools.ietf.org/html/rfc3327) - Session Initiation Protocol (SIP) Extension Header Field for Registering Non-Adjacent Contacts
  * [RFC3608](http://tools.ietf.org/html/rfc3608) - Session Initiation Protocol (SIP) Extension Header Field for Service Route Discovery During Registration

Tech-invite - http://www.tech-invite.com/

# ToDo #

Following points are waiting for implementation
  * predefined route set and outbound proxy used as singe route in route set
  * dialogs support
  * check: If more than one Via header field value is present in a response, the UAC SHOULD discard the message.
  * processing of 3xx responses
  * process merged requests (sip rfc 8.2.2.2)

# Resources #

Perl Net::SIP
PJSIP http://www.pjsip.org/
PJSUA Python Module http://trac.pjsip.org/repos/wiki/Python_SIP_Tutorial