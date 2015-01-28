LDAP Multi Search Base
======================

This Alfresco AMP module overrides the default beans for LDAP authentication/synchronization to allow authentication and synchronization of multiple user and group search bases within a single subsystem.

*Disclaimer*: This module has undergone limited testing. Use at your own risk.

Configuration
-------------------

The LDAP subsystem in the authentication chain must be named "ldap1" for this to work. Multiple `ldap-multi-search-base` LDAP subsystems are not yet supported.

In alfresco-global.properties:
Both `ldap.synchronization.userSearchBase` and `ldap.synchronization.groupSearchBase` can take multiple distinguished names, which must be separated by a colon (`:`).

For example:

    authentication.chain=alfrescoNtlm1:alfrescoNtlm,ldap1:ldap
    ldap.synchronization.userSearchBase=ou\=mathematicians,dc\=example,dc\=com:ou\=scientists,dc\=example,dc\=com
    ldap.synchronization.groupSearchBase=ou\=mathematicians,dc\=example,dc\=com:ou\=scientists,dc\=example,dc\=com
