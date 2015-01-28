This Alfresco AMP module overrides the default beans for LDAP authentication/synchronization to allow authentication and synchronization of multiple search bases within the same subsystem.

Note: The LDAP subsystem in the authentication chain must be named "ldap1" for this to work. Multiple subsystems are not yet supported.

In alfresco-global.properties:
Both ldap.synchronization.userSearchBase and ldap.synchronization.groupSearchBase can take multiple distinguished names, which must be separated by a colon (":").

For example:
ldap.synchronization.userSearchBase=ou\=mathematicians,dc\=example,dc\=com:ou\=scientists,dc\=example,dc\=com
ldap.synchronization.groupSearchBase=ou\=mathematicians,dc\=example,dc\=com:ou\=scientists,dc\=example,dc\=com


