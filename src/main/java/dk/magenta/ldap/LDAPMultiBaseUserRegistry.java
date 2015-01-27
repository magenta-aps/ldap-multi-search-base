/*
 * Copyright (C) 2005-2014 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
package dk.magenta.ldap;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.model.ContentModel;
import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AuthenticationDiagnostic;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.ldap.LDAPInitialDirContextFactory;
import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.repo.security.sync.UserRegistry;
import org.alfresco.repo.security.sync.ldap.LDAPNameResolver;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
import org.alfresco.util.PropertyMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

/**
 * A {@link org.alfresco.repo.security.sync.UserRegistry} implementation with the ability to query Alfresco-like descriptions of users and groups from
 * an LDAP directory, optionally restricted to those modified since a certain time.
 *
 * @author dward
 */
public class LDAPMultiBaseUserRegistry implements UserRegistry, LDAPNameResolver, InitializingBean, ActivateableBean
{

    /** The logger. */
    private static Log logger = LogFactory.getLog(LDAPMultiBaseUserRegistry.class);

    /** The regular expression that will match the attribute at the end of a range. */
    private static final Pattern PATTERN_RANGE_END = Pattern.compile(";range=[0-9]+-\\*");

    /** Is this bean active? I.e. should this part of the subsystem be used? */
    private boolean active = true;

    /** Enable progress estimation? When enabled, the user query has to be run twice in order to count entries. */
    private boolean enableProgressEstimation = true;

    /** The group query. */
    private String groupQuery = "(objectclass=groupOfNames)";

    /** The group differential query. */
    private String groupDifferentialQuery = "(&(objectclass=groupOfNames)(!(modifyTimestamp<={0})))";

    /** The person query. */
    private String personQuery = "(objectclass=inetOrgPerson)";

    /** The person differential query. */
    private String personDifferentialQuery = "(&(objectclass=inetOrgPerson)(!(modifyTimestamp<={0})))";

    /** The group search base. */
    private String groupSearchBase;

    /** The group search bases. */
    private String[] groupSearchBases;

    /** The user search base. */
    private String userSearchBase;

    /** The user search bases. */
    private String[] userSearchBases;

    /** The group id attribute name. */
    private String groupIdAttributeName = "cn";

    /** The user id attribute name. */
    private String userIdAttributeName = "uid";

    /** The member attribute name. */
    private String memberAttributeName = "member";

    /** The modification timestamp attribute name. */
    private String modifyTimestampAttributeName = "modifyTimestamp";

    /** The group type. */
    private String groupType = "groupOfNames";

    /** The person type. */
    private String personType = "inetOrgPerson";

    /** The ldap initial context factory. */
    private LDAPInitialDirContextFactory ldapInitialContextFactory;

    /** The namespace service. */
    private NamespaceService namespaceService;

    /** The person attribute mapping. */
    private Map<String, String> personAttributeMapping;

    /** The person attribute defaults. */
    private Map<String, String> personAttributeDefaults = Collections.emptyMap();

    /** The group attribute mapping. */
    private Map<String, String> groupAttributeMapping;

    /** The group attribute defaults. */
    private Map<String, String> groupAttributeDefaults = Collections.emptyMap();

    /**
     * The query batch size. If positive, indicates that RFC 2696 paged results should be used to split query results
     * into batches of the specified size. Overcomes any size limits imposed by the LDAP server.
     */
    private int queryBatchSize;

    /**
     * The attribute retrieval batch size. If positive, indicates that range retrieval should be used to fetch
     * multi-valued attributes (such as member) in batches of the specified size. Overcomes any size limits imposed by
     * the LDAP server.
     */
    private int attributeBatchSize;

    /** Should we error on missing group members?. */
    private boolean errorOnMissingMembers;

    /** Should we error on duplicate group IDs?. */
    private boolean errorOnDuplicateGID;

    /** Should we error on missing group IDs?. */
    private boolean errorOnMissingGID = false;

    /** Should we error on missing user IDs?. */
    private boolean errorOnMissingUID = false;

    /** An array of all LDAP attributes to be queried from users plus a set of property QNames. */
    private Pair<String[], Set<QName>> userKeys;

    /** An array of all LDAP attributes to be queried from groups plus a set of property QNames. */
    private Pair<String[], Set<QName>> groupKeys;

    /** The LDAP generalized time format. */
    private DateFormat timestampFormat;

    /**
     * Instantiates a new lDAP user registry.
     */
    public LDAPMultiBaseUserRegistry()
    {
        // Default to official LDAP generalized time format (unfortunately not used by Active Directory)
        setTimestampFormat("yyyyMMddHHmmss'Z'");
    }

    /**
     * Controls whether this bean is active. I.e. should this part of the subsystem be used?
     *
     * @param active
     *            <code>true</code> if this bean is active
     */
    public void setActive(boolean active)
    {
        this.active = active;
    }

    /**
     * Controls whether progress estimation is enabled. When enabled, the user query has to be run twice in order to
     * count entries.
     *
     * @param enableProgressEstimation
     *            <code>true</code> if progress estimation is enabled
     */
    public void setEnableProgressEstimation(boolean enableProgressEstimation)
    {
        this.enableProgressEstimation = enableProgressEstimation;
    }

    /**
     * Sets the group id attribute name.
     *
     * @param groupIdAttributeName
     *            the group id attribute name
     */
    public void setGroupIdAttributeName(String groupIdAttributeName)
    {
        this.groupIdAttributeName = groupIdAttributeName;
    }

    /**
     * Sets the group query.
     *
     * @param groupQuery
     *            the group query
     */
    public void setGroupQuery(String groupQuery)
    {
        this.groupQuery = groupQuery;
    }

    /**
     * Sets the group differential query.
     *
     * @param groupDifferentialQuery
     *            the group differential query
     */
    public void setGroupDifferentialQuery(String groupDifferentialQuery)
    {
        this.groupDifferentialQuery = groupDifferentialQuery;
    }

    /**
     * Sets the person query.
     *
     * @param personQuery
     *            the person query
     */
    public void setPersonQuery(String personQuery)
    {
        this.personQuery = personQuery;
    }

    /**
     * Sets the person differential query.
     *
     * @param personDifferentialQuery
     *            the person differential query
     */
    public void setPersonDifferentialQuery(String personDifferentialQuery)
    {
        this.personDifferentialQuery = personDifferentialQuery;
    }

    /**
     * Sets the group type.
     *
     * @param groupType
     *            the group type
     */
    public void setGroupType(String groupType)
    {
        this.groupType = groupType;
    }

    /**
     * Sets the member attribute name.
     *
     * @param memberAttribute
     *            the member attribute name
     */
    public void setMemberAttribute(String memberAttribute)
    {
        this.memberAttributeName = memberAttribute;
    }

    /**
     * Sets the person type.
     *
     * @param personType
     *            the person type
     */
    public void setPersonType(String personType)
    {
        this.personType = personType;
    }

    /**
     * Sets the group search base.
     *
     * @param groupSearchBase
     *            the group search base
     */
    public void setGroupSearchBase(String groupSearchBase)
    {
        this.groupSearchBases = groupSearchBase.split(":");
        this.groupSearchBase = groupSearchBase;
    }

    /**
     * Sets the user search base.
     *
     * @param userSearchBase
     *            the user search base
     */
    public void setUserSearchBase(String userSearchBase)
    {
        this.userSearchBases = userSearchBase.split(":");
        this.userSearchBase = userSearchBase;
    }

    /**
     * Sets the user id attribute name.
     *
     * @param userIdAttributeName
     *            the user id attribute name
     */
    public void setUserIdAttributeName(String userIdAttributeName)
    {
        this.userIdAttributeName = userIdAttributeName;
    }

    /**
     * Sets the modification timestamp attribute name.
     *
     * @param modifyTimestampAttributeName
     *            the modification timestamp attribute name
     */
    public void setModifyTimestampAttributeName(String modifyTimestampAttributeName)
    {
        this.modifyTimestampAttributeName = modifyTimestampAttributeName;
    }

    /**
     * Sets the timestamp format. Unfortunately, this varies between directory servers.
     *
     * @param timestampFormat
     *            the timestamp format
     *            <ul>
     *            <li>OpenLDAP: "yyyyMMddHHmmss'Z'"
     *            <li>Active Directory: "yyyyMMddHHmmss'.0Z'"
     *            </ul>
     */
    public void setTimestampFormat(String timestampFormat)
    {
        this.timestampFormat = new SimpleDateFormat(timestampFormat, Locale.UK);
        this.timestampFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    }

    /**
     * Decides whether to error on missing group members.
     *
     * @param errorOnMissingMembers
     *            <code>true</code> if we should error on missing group members
     */
    public void setErrorOnMissingMembers(boolean errorOnMissingMembers)
    {
        this.errorOnMissingMembers = errorOnMissingMembers;
    }

    /**
     * Decides whether to error on missing group IDs.
     *
     * @param errorOnMissingGID
     *            <code>true</code> if we should error on missing group IDs
     */
    public void setErrorOnMissingGID(boolean errorOnMissingGID)
    {
        this.errorOnMissingGID = errorOnMissingGID;
    }

    /**
     * Decides whether to error on missing user IDs.
     *
     * @param errorOnMissingUID
     *            <code>true</code> if we should error on missing user IDs
     */
    public void setErrorOnMissingUID(boolean errorOnMissingUID)
    {
        this.errorOnMissingUID = errorOnMissingUID;
    }

    /**
     * Decides whether to error on duplicate group IDs.
     *
     * @param errorOnDuplicateGID
     *            <code>true</code> if we should error on duplicate group IDs
     */
    public void setErrorOnDuplicateGID(boolean errorOnDuplicateGID)
    {
        this.errorOnDuplicateGID = errorOnDuplicateGID;
    }

    /**
     * Sets the LDAP initial dir context factory.
     *
     * @param ldapInitialDirContextFactory
     *            the new LDAP initial dir context factory
     */
    public void setLDAPInitialDirContextFactory(LDAPInitialDirContextFactory ldapInitialDirContextFactory)
    {
        this.ldapInitialContextFactory = ldapInitialDirContextFactory;
    }

    /**
     * Sets the namespace service.
     *
     * @param namespaceService
     *            the namespace service
     */
    public void setNamespaceService(NamespaceService namespaceService)
    {
        this.namespaceService = namespaceService;
    }

    /**
     * Sets the person attribute defaults.
     *
     * @param personAttributeDefaults
     *            the person attribute defaults
     */
    public void setPersonAttributeDefaults(Map<String, String> personAttributeDefaults)
    {
        this.personAttributeDefaults = personAttributeDefaults;
    }

    /**
     * Sets the person attribute mapping.
     *
     * @param personAttributeMapping
     *            the person attribute mapping
     */
    public void setPersonAttributeMapping(Map<String, String> personAttributeMapping)
    {
        this.personAttributeMapping = personAttributeMapping;
    }

    /**
     * Sets the group attribute defaults.
     *
     * @param groupAttributeDefaults
     *            the group attribute defaults
     */
    public void setGroupAttributeDefaults(Map<String, String> groupAttributeDefaults)
    {
        this.groupAttributeDefaults = groupAttributeDefaults;
    }

    /**
     * Sets the group attribute mapping.
     *
     * @param groupAttributeMapping
     *            the group attribute mapping
     */
    public void setGroupAttributeMapping(Map<String, String> groupAttributeMapping)
    {
        this.groupAttributeMapping = groupAttributeMapping;
    }

    /**
     * Sets the query batch size.
     *
     * @param queryBatchSize
     *            If positive, indicates that RFC 2696 paged results should be used to split query results into batches
     *            of the specified size. Overcomes any size limits imposed by the LDAP server.
     */
    public void setQueryBatchSize(int queryBatchSize)
    {
        this.queryBatchSize = queryBatchSize;
    }

    /**
     * Sets the attribute batch size.
     *
     * @param attributeBatchSize
     *            If positive, indicates that range retrieval should be used to fetch multi-valued attributes (such as
     *            member) in batches of the specified size. Overcomes any size limits imposed by the LDAP server.
     */
    public void setAttributeBatchSize(int attributeBatchSize)
    {
        this.attributeBatchSize = attributeBatchSize;
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.repo.management.subsystems.ActivateableBean#isActive()
     */
    public boolean isActive()
    {
        return this.active;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    public void afterPropertiesSet() throws Exception
    {
        if (this.personAttributeMapping == null)
        {
            this.personAttributeMapping = new HashMap<String, String>(5);
        }
        this.personAttributeMapping.put(ContentModel.PROP_USERNAME.toPrefixString(this.namespaceService),
                this.userIdAttributeName);
        this.userKeys = initKeys(this.personAttributeMapping);

        // Include a range restriction for the multi-valued member attribute if this is enabled
        if (this.groupAttributeMapping == null)
        {
            this.groupAttributeMapping = new HashMap<String, String>(5);
        }
        this.groupAttributeMapping.put(ContentModel.PROP_AUTHORITY_NAME.toPrefixString(this.namespaceService),
                this.groupIdAttributeName);
        this.groupKeys = initKeys(this.groupAttributeMapping,
                this.attributeBatchSize > 0 ? this.memberAttributeName + ";range=0-" + (this.attributeBatchSize - 1)
                        : this.memberAttributeName);
    }


    /* (non-Javadoc)
     * @see org.alfresco.repo.security.sync.UserRegistry#getPersonMappedProperties()
     */
    public Set<QName> getPersonMappedProperties()
    {
        return this.userKeys.getSecond();
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.repo.security.sync.UserRegistry#getPersons(java.util.Date)
     */
    public Collection<NodeDescription> getPersons(Date modifiedSince)
    {
        return new PersonCollection(modifiedSince);
    }


    /* (non-Javadoc)
     * @see org.alfresco.repo.security.sync.UserRegistry#getPersonNames()
     */
    public Collection<String> getPersonNames()
    {
        final List<String> personNames = new LinkedList<String>();
        processQuery(new SearchCallback()
        {
            public void process(SearchResult result) throws NamingException, ParseException
            {
                Attribute nameAttribute = result.getAttributes().get(LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                if (nameAttribute == null)
                {
                    if (LDAPMultiBaseUserRegistry.this.errorOnMissingUID)
                    {
                        Object[] params = {result.getNameInNamespace(), LDAPMultiBaseUserRegistry.this.userIdAttributeName};
                        throw new AlfrescoRuntimeException("synchronization.err.ldap.get.user.id.missing", params);
                    }
                    else
                    {
                        LDAPMultiBaseUserRegistry.logger.warn("User missing user id attribute DN ="
                                + result.getNameInNamespace() + "  att = " + LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                    }
                }
                else
                {
                    if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                    {
                        LDAPMultiBaseUserRegistry.logger.debug("Person DN recognized: " + nameAttribute.get());
                    }
                    personNames.add((String) nameAttribute.get());
                }
            }

            public void close() throws NamingException
            {
            }

        }, this.userSearchBases, this.personQuery, new String[]
        {
            this.userIdAttributeName
        });
        return personNames;
    }

    /* (non-Javadoc)
     * @see org.alfresco.repo.security.sync.UserRegistry#getGroupNames()
     */
    public Collection<String> getGroupNames()
    {
        final List<String> groupNames = new LinkedList<String>();
        processQuery(new SearchCallback()
        {

            public void process(SearchResult result) throws NamingException, ParseException
            {
                Attribute nameAttribute = result.getAttributes().get(LDAPMultiBaseUserRegistry.this.groupIdAttributeName);
                if (nameAttribute == null)
                {
                    if (LDAPMultiBaseUserRegistry.this.errorOnMissingGID)
                    {
                        Object[] params = {result.getNameInNamespace(), LDAPMultiBaseUserRegistry.this.groupIdAttributeName};
                        throw new AlfrescoRuntimeException("synchronization.err.ldap.get.group.id.missing", params);
                    }
                    else
                    {
                        LDAPMultiBaseUserRegistry.logger.warn("Missing GID on " + result.getNameInNamespace());
                    }
                }
                else
                {
                    String authority = "GROUP_" + (String) nameAttribute.get();
                    if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                    {
                        LDAPMultiBaseUserRegistry.logger.debug("Group DN recognized: " + authority);
                    }
                    groupNames.add(authority);
                }
            }

            public void close() throws NamingException
            {
            }

        }, this.groupSearchBases, this.groupQuery, new String[]
        {
            this.groupIdAttributeName
        });
        return groupNames;
    }

    private boolean nameStartsWithNameInSet(LdapName name, Set<LdapName>s1) {
        for (LdapName n : s1) {
            if (name.startsWith(n)) {
                return true;
            }
        }
        return false;
    }

    private boolean removeDistjointNamesFromSets(Set<LdapName> s1, Set<LdapName> s2) {
        Set<LdapName> copyS1 = new LinkedHashSet<>(s1);
        Set<LdapName> copyS2 = new LinkedHashSet<>(s2);
        for (LdapName n1 : copyS1) {
            for (LdapName n2 : copyS2) {
                if (n1.startsWith(n2) || n2.startsWith(n1)) {
                    s1.remove(n1);
                    s2.remove(n2);
                }
            }
        }
        return !s1.isEmpty() && !s2.isEmpty();
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.repo.security.sync.UserRegistry#getGroups(java.util.Date)
     */
    public Collection<NodeDescription> getGroups(Date modifiedSince)
    {
        // Work out whether the user and group trees are disjoint. This may allow us to optimize reverse DN
        // resolution.
        final Set<LdapName> groupDistinguishedNamePrefixes = new LinkedHashSet<>();
        for (String groupSearchBase : this.groupSearchBases) {
            try {
                final LdapName groupDistinguishedNamePrefix = fixedLdapName(groupSearchBase.toLowerCase());
                groupDistinguishedNamePrefixes.add(groupDistinguishedNamePrefix);
            } catch (InvalidNameException e) {
                Object[] params = {groupSearchBase.toLowerCase(), e.getLocalizedMessage()};
                throw new AlfrescoRuntimeException("synchronization.err.ldap.search.base.invalid", params, e);
            }
        }
        final Set<LdapName> userDistinguishedNamePrefixes = new LinkedHashSet<>();
        for (String userSearchBase : this.userSearchBases) {
            try {
                final LdapName userDistinguishedNamePrefix = fixedLdapName(userSearchBase.toLowerCase());
                userDistinguishedNamePrefixes.add(userDistinguishedNamePrefix);
            } catch (InvalidNameException e) {
                Object[] params = {userSearchBase.toLowerCase(), e.getLocalizedMessage()};
                throw new AlfrescoRuntimeException("synchronization.err.ldap.search.base.invalid", params, e);
            }
        }

        final Set<LdapName> distinctGroupDNPrefixes = new LinkedHashSet<>(groupDistinguishedNamePrefixes);
        final Set<LdapName> distinctUserDNPrefixes = new LinkedHashSet<>(userDistinguishedNamePrefixes);
        final boolean disjoint = removeDistjointNamesFromSets(distinctGroupDNPrefixes, distinctUserDNPrefixes);

        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled()) {
            LDAPMultiBaseUserRegistry.logger.debug("Groups and users search " +
                    "bases are disjoint? " + disjoint);
        }

        // Choose / generate the query
        String query;
        if (modifiedSince == null)
        {
            query = this.groupQuery;
        }
        else
        {
            query = MessageFormat.format(this.groupDifferentialQuery, this.timestampFormat.format(modifiedSince));
        }

        // Run the query and process the results
        final Map<String, NodeDescription> lookup = new TreeMap<String, NodeDescription>();
        processQuery(new SearchCallback()
        {
            // We get a whole new context to avoid interference with cookies from paged results
            private DirContext ctx = LDAPMultiBaseUserRegistry.this.ldapInitialContextFactory.getDefaultIntialDirContext();

            public void process(SearchResult result) throws NamingException, ParseException
            {
                Attributes attributes = result.getAttributes();
                Attribute gidAttribute = attributes.get(LDAPMultiBaseUserRegistry.this.groupIdAttributeName);
                if (gidAttribute == null)
                {
                    if (LDAPMultiBaseUserRegistry.this.errorOnMissingGID)
                    {
                        Object[] params = {result.getNameInNamespace(), LDAPMultiBaseUserRegistry.this.groupIdAttributeName};
                        throw new AlfrescoRuntimeException("synchronization.err.ldap.get.group.id.missing", params);
                    }
                    else
                    {
                        LDAPMultiBaseUserRegistry.logger.warn("Missing GID on " + attributes);
                        return;
                    }
                }
                String groupShortName = gidAttribute.get(0).toString();
                String gid = "GROUP_" + groupShortName;

                NodeDescription group = lookup.get(gid);
                if (group == null)
                {
                    // Apply the mapped properties to the node description
                    group = mapToNode(LDAPMultiBaseUserRegistry.this.groupAttributeMapping,
                            LDAPMultiBaseUserRegistry.this.groupAttributeDefaults, result);

                    // Make sure the "GROUP_" prefix is applied
                    group.getProperties().put(ContentModel.PROP_AUTHORITY_NAME, gid);
                    lookup.put(gid, group);
                }
                else if (LDAPMultiBaseUserRegistry.this.errorOnDuplicateGID)
                {
                    throw new AlfrescoRuntimeException("Duplicate group id found for " + gid);
                }
                else
                {
                    LDAPMultiBaseUserRegistry.logger.warn("Duplicate gid found for " + gid + " -> merging definitions");
                }

                Set<String> childAssocs = group.getChildAssociations();

                // Get the repeating (and possibly range restricted) member attribute
                Attribute memAttribute = getRangeRestrictedAttribute(attributes,
                        LDAPMultiBaseUserRegistry.this.memberAttributeName);
                int nextStart = LDAPMultiBaseUserRegistry.this.attributeBatchSize;
                if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                {
                    LDAPMultiBaseUserRegistry.logger.debug("Processing group: " + gid +
                            ", from source: " + group.getSourceId());
                }
                // Loop until we get to the end of the range
                while (memAttribute != null)
                {
                    for (int i = 0; i < memAttribute.size(); i++)
                    {
                        String attribute = (String) memAttribute.get(i);
                        if (attribute != null && attribute.length() > 0)
                        {
                            try
                            {
                                // Attempt to parse the member attribute as a DN. If this fails we have a fallback
                                // in the catch block
                                LdapName distinguishedNameForComparison = fixedLdapName(attribute.toLowerCase());
                                Attribute nameAttribute;

                                // If the user and group search bases are different we may be able to recognize user
                                // and group DNs without a secondary lookup
                                if (disjoint)
                                {
                                    LdapName distinguishedName = fixedLdapName(attribute);
                                    Attributes nameAttributes = distinguishedName.getRdn(distinguishedName.size() - 1)
                                            .toAttributes();

                                    // Recognize user DNs
                                    if (nameStartsWithNameInSet(distinguishedNameForComparison, distinctUserDNPrefixes)
                                            && (nameAttribute = nameAttributes
                                                    .get(LDAPMultiBaseUserRegistry.this.userIdAttributeName)) != null)
                                    {
                                        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                                        {
                                            LDAPMultiBaseUserRegistry.logger.debug("User DN recognized: " + nameAttribute.get());
                                        }
                                        childAssocs.add((String) nameAttribute.get());
                                        continue;
                                    }

                                    // Recognize group DNs
                                    if (nameStartsWithNameInSet(distinguishedNameForComparison, distinctGroupDNPrefixes)
                                            && (nameAttribute = nameAttributes
                                                    .get(LDAPMultiBaseUserRegistry.this.groupIdAttributeName)) != null)
                                    {
                                        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                                        {
                                            LDAPMultiBaseUserRegistry.logger.debug("Group DN recognized: " + "GROUP_" + nameAttribute.get());
                                        }
                                        childAssocs.add("GROUP_" + nameAttribute.get());
                                        continue;
                                    }
                                }

                                // If we can't determine the name and type from the DN alone, try a directory lookup
                                if (nameStartsWithNameInSet(distinguishedNameForComparison, userDistinguishedNamePrefixes)
                                        || nameStartsWithNameInSet(distinguishedNameForComparison, groupDistinguishedNamePrefixes))
                                {
                                    try
                                    {
                                        Attributes childAttributes = this.ctx.getAttributes(jndiName(attribute),
                                                new String[]
                                                {
                                                    "objectclass", LDAPMultiBaseUserRegistry.this.groupIdAttributeName,
                                                    LDAPMultiBaseUserRegistry.this.userIdAttributeName
                                                });
                                        Attribute objectClass = childAttributes.get("objectclass");
                                        if (hasAttributeValue(objectClass, LDAPMultiBaseUserRegistry.this.personType))
                                        {
                                            nameAttribute = childAttributes
                                                    .get(LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                                            if (nameAttribute == null)
                                            {
                                                if (LDAPMultiBaseUserRegistry.this.errorOnMissingUID)
                                                {
                                                    throw new AlfrescoRuntimeException(
                                                            "User missing user id attribute DN =" + attribute
                                                                    + "  att = "
                                                                    + LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                                                }
                                                else
                                                {
                                                    LDAPMultiBaseUserRegistry.logger.warn("User missing user id attribute DN ="
                                                            + attribute + "  att = "
                                                            + LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                                                    continue;
                                                }
                                            }
                                            if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                                            {
                                                LDAPMultiBaseUserRegistry.logger.debug("User DN recognized by directory lookup: " + nameAttribute.get());
                                            }
                                            childAssocs.add((String) nameAttribute.get());
                                            continue;
                                        }
                                        else if (hasAttributeValue(objectClass, LDAPMultiBaseUserRegistry.this.groupType))
                                        {
                                            nameAttribute = childAttributes
                                                    .get(LDAPMultiBaseUserRegistry.this.groupIdAttributeName);
                                            if (nameAttribute == null)
                                            {
                                                if (LDAPMultiBaseUserRegistry.this.errorOnMissingGID)
                                                {
                                                    Object[] params = {result.getNameInNamespace(), LDAPMultiBaseUserRegistry.this.groupIdAttributeName};
                                                    throw new AlfrescoRuntimeException("synchronization.err.ldap.get.group.id.missing", params);
                                                }
                                                else
                                                {
                                                    LDAPMultiBaseUserRegistry.logger.warn("Missing GID on " + childAttributes);
                                                    continue;
                                                }
                                            }
                                            if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                                            {
                                                LDAPMultiBaseUserRegistry.logger.debug("Group DN recognized by directory lookup: " + "GROUP_" + nameAttribute.get());
                                            }
                                            childAssocs.add("GROUP_" + nameAttribute.get());
                                            continue;
                                        }
                                    }
                                    catch (NamingException e)
                                    {
                                        // Unresolvable name
                                        if (LDAPMultiBaseUserRegistry.this.errorOnMissingMembers)
                                        {
                                            Object[] params = {groupShortName, attribute, e.getLocalizedMessage() };
                                            throw new AlfrescoRuntimeException("synchronization.err.ldap.group.member.missing.exception", params, e);
                                        }
                                        LDAPMultiBaseUserRegistry.logger.warn("Failed to resolve member of group '"
                                                + groupShortName + "' with distinguished name: " + attribute, e);
                                        continue;
                                    }
                                }
                                if (LDAPMultiBaseUserRegistry.this.errorOnMissingMembers)
                                {
                                    Object[] params = {groupShortName, attribute};
                                    throw new AlfrescoRuntimeException("synchronization.err.ldap.group.member.missing", params);
                                }
                                LDAPMultiBaseUserRegistry.logger.warn("Failed to resolve member of group '" + groupShortName
                                        + "' with distinguished name: " + attribute);
                            }
                            catch (InvalidNameException e)
                            {
                                // The member attribute didn't parse as a DN. So assume we have a group class like
                                // posixGroup (FDS) that directly lists user names
                                if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                                {
                                    LDAPMultiBaseUserRegistry.logger.debug("Member DN recognized as posixGroup: " + attribute);
                                }
                                childAssocs.add(attribute);
                            }
                        }
                    }

                    // If we are using attribute matching and we haven't got to the end (indicated by an asterisk),
                    // fetch the next batch
                    if (nextStart > 0
                            && !LDAPMultiBaseUserRegistry.PATTERN_RANGE_END.matcher(memAttribute.getID().toLowerCase()).find())
                    {
                        Attributes childAttributes = this.ctx.getAttributes(jndiName(result.getNameInNamespace()),
                                new String[]
                                {
                                    LDAPMultiBaseUserRegistry.this.memberAttributeName + ";range=" + nextStart + '-'
                                            + (nextStart + LDAPMultiBaseUserRegistry.this.attributeBatchSize - 1)
                                });
                        memAttribute = getRangeRestrictedAttribute(childAttributes,
                                LDAPMultiBaseUserRegistry.this.memberAttributeName);
                        nextStart += LDAPMultiBaseUserRegistry.this.attributeBatchSize;
                    }
                    else
                    {
                        memAttribute = null;
                    }
                }
            }

            public void close() throws NamingException
            {
                this.ctx.close();
            }
        }, this.groupSearchBases, query, this.groupKeys.getFirst());

        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
        {
            LDAPMultiBaseUserRegistry.logger.debug("Found " + lookup.size());
        }

        return lookup.values();
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.repo.security.sync.ldap.LDAPNameResolver#resolveDistinguishedName(java.lang.String)
     */
    public String resolveDistinguishedName(String userId, AuthenticationDiagnostic diagnostic) throws AuthenticationException
    {
        if(logger.isDebugEnabled())
        {
            logger.debug("resolveDistinguishedName userId:" + userId);
        }
        SearchControls userSearchCtls = new SearchControls();
        userSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // Although we don't actually need any attributes, we ask for the UID for compatibility with Sun Directory Server. See ALF-3868
        userSearchCtls.setReturningAttributes(new String[]
        {
            this.userIdAttributeName
        });

        InitialDirContext ctx = null;

        for (String userSearchBase : this.userSearchBases) {

            String query = userSearchBase + "(&" + this.personQuery
                    + "(" + this.userIdAttributeName + "= userId))";

            NamingEnumeration<SearchResult> searchResults = null;
            SearchResult result = null;

            try {
                ctx = this.ldapInitialContextFactory.getDefaultIntialDirContext(diagnostic);

                // Execute the user query with an additional condition that ensures only the user with the required ID is
                // returned. Force RFC 2254 escaping of the user ID in the filter to avoid any manipulation

                searchResults = ctx.search(userSearchBase, "(&" + this.personQuery
                        + "(" + this.userIdAttributeName + "={0}))", new Object[]
                        {
                                userId
                        }, userSearchCtls);

                if (searchResults.hasMore()) {
                    result = searchResults.next();
                    Attributes attributes = result.getAttributes();
                    Attribute uidAttribute = attributes.get(this.userIdAttributeName);
                    if (uidAttribute == null) {
                        if (this.errorOnMissingUID) {
                            throw new AlfrescoRuntimeException(
                                    "User returned by user search does not have mandatory user id attribute "
                                            + attributes);
                        } else {
                            LDAPMultiBaseUserRegistry.logger
                                    .warn("User returned by user search does not have mandatory user id attribute "
                                            + attributes);
                        }
                    }
                    // MNT:2597 We don't trust the LDAP server's treatment of whitespace, accented characters etc. We will
                    // only resolve this user if the user ID matches
                    else if (userId.equalsIgnoreCase((String) uidAttribute.get(0))) {
                        String name = result.getNameInNamespace();

                        // Close the contexts, see ALF-20682
                        Context context = (Context) result.getObject();
                        if (context != null) {
                            context.close();
                        }
                        result = null;
                        return name;
                    }

                    // Close the contexts, see ALF-20682
                    Context context = (Context) result.getObject();
                    if (context != null) {
                        context.close();
                    }
                    result = null;
                }
            } catch (NamingException e) {
                // Connection is good here - AuthenticationException would be thrown by ldapInitialContextFactory

                Object[] args1 = {userId, query};
                diagnostic.addStep(AuthenticationDiagnostic.STEP_KEY_LDAP_SEARCH, false, args1);
            }

            if (result != null) {
                try {
                    Context context = (Context) result.getObject();
                    if (context != null) {
                        context.close();
                    }
                } catch (Exception e) {
                    logger.debug("error when closing result block context", e);
                }
            }
            if (searchResults != null) {
                try {
                    searchResults.close();
                } catch (Exception e) {
                    logger.debug("error when closing searchResults context", e);
                }
            }
        }

        if (ctx != null) {
            try {
                ctx.close();
            } catch (NamingException e) {
                logger.debug("error when closing ldap context", e);
            }
        }

        // failed to search
//        Object[] args = {e.getLocalizedMessage()};
        throw new AuthenticationException("authentication.err.connection.ldap.search", diagnostic);
    }

    private Pair<String[], Set<QName>> initKeys(Map<String, String> attributeMapping,
            String... extraAttibutes)
    {
        // Compile a complete array of LDAP attribute names, including operational attributes
        Set<String> attributeSet = new TreeSet<String>();
        attributeSet.addAll(Arrays.asList(extraAttibutes));
        attributeSet.add(this.modifyTimestampAttributeName);
        for (String attribute : attributeMapping.values())
        {
            if (attribute != null)
            {
                attributeSet.add(attribute);
            }
        }
        String[] attributeNames = new String[attributeSet.size()];
        attributeSet.toArray(attributeNames);

        // Create a set with the property names converted to QNames
        Set<QName> qnames = new HashSet<QName>(attributeMapping.size() * 2);
        for (String property : attributeMapping.keySet())
        {
            qnames.add(QName.createQName(property, this.namespaceService));
        }

        return new Pair<String[], Set<QName>>(attributeNames, qnames);
    }

    private NodeDescription mapToNode(Map<String, String> attributeMapping, Map<String, String> attributeDefaults,
            SearchResult result) throws NamingException
    {
        NodeDescription nodeDescription = new NodeDescription(result.getNameInNamespace());
        Attributes ldapAttributes = result.getAttributes();

        // Parse the timestamp
        Attribute modifyTimestamp = ldapAttributes.get(this.modifyTimestampAttributeName);
        if (modifyTimestamp != null)
        {
            try
            {
                nodeDescription.setLastModified(this.timestampFormat.parse(modifyTimestamp.get().toString()));
            }
            catch (ParseException e)
            {
                throw new AlfrescoRuntimeException("Failed to parse timestamp.", e);
            }
        }

        // Apply the mapped attributes
        PropertyMap properties = nodeDescription.getProperties();
        for (String key : attributeMapping.keySet())
        {
            QName keyQName = QName.createQName(key, this.namespaceService);

            // cater for null
            String attributeName = attributeMapping.get(key);
            if (attributeName != null)
            {
                Attribute attribute = ldapAttributes.get(attributeName);
                if (attribute != null)
                {
                    String value = (String) attribute.get(0);
                    if (value != null)
                    {
                        properties.put(keyQName, value);
                    }
                }
                else
                {
                    String defaultValue = attributeDefaults.get(key);
                    if (defaultValue != null)
                    {
                        properties.put(keyQName, defaultValue);
                    }
                }
            }
            else
            {
                String defaultValue = attributeDefaults.get(key);
                if (defaultValue != null)
                {
                    properties.put(keyQName, defaultValue);
                }
            }
        }
        return nodeDescription;
    }

    /**
     * Converts a given DN into one suitable for use through JNDI. In particular, escapes special characters such as '/'
     * which have special meaning to JNDI.
     *
     * @param dn
     *            the dn
     * @return the name
     * @throws javax.naming.InvalidNameException
     *             the invalid name exception
     */
    private static Name jndiName(String dn) throws InvalidNameException
    {
        Name n = new CompositeName();
        n.add(dn);
        return n;
    }

    /**
     * Works around a bug in the JDK DN parsing. If an RDN has trailing escaped whitespace in the format "\\20" then
     * LdapName would normally strip this. This method works around this by replacing "\\20" with "\\ " and "\\0D" with
     * "\\\r".
     *
     * @param dn
     *            the DN
     * @return the parsed ldap name
     * @throws javax.naming.InvalidNameException
     *             if the DN is invalid
     */
    private static LdapName fixedLdapName(String dn) throws InvalidNameException
    {
        // Optimization for DNs without escapes in them
        if (dn.indexOf('\\') == -1)
        {
            return new LdapName(dn);
        }

        StringBuilder fixed = new StringBuilder(dn.length());
        int length = dn.length();
        for (int i = 0; i < length; i++)
        {
            char c = dn.charAt(i);
            char c1, c2;
            if (c == '\\')
            {
                if (i + 2 < length && Character.isLetterOrDigit(c1 = dn.charAt(i + 1))
                        && Character.isLetterOrDigit(c2 = dn.charAt(i + 2)))
                {
                    if (c1 == '2' && c2 == '0')
                    {
                        fixed.append("\\ ");
                    }
                    else if (c1 == '0' && c2 == 'D')
                    {
                        fixed.append("\\\r");
                    }
                    else
                    {
                        fixed.append(dn, i, i + 3);
                    }
                    i += 2;
                }
                else if (i + 1 < length)
                {
                    fixed.append(dn, i, i + 2);
                    i += 1;
                }
                else
                {
                    fixed.append(c);
                }
            }
            else
            {
                fixed.append(c);
            }
        }
        return new LdapName(fixed.toString());
    }

    /**
     * Invokes the given callback on each entry returned by the given query.
     *
     * @param callback
     *            the callback
     * @param searchBases
     *            the base DNs for the search
     * @param query
     *            the query
     * @param returningAttributes
     *            the attributes to include in search results
     * @throws org.alfresco.error.AlfrescoRuntimeException
     */
    private void processQuery(SearchCallback callback, String searchBases[],
                              String query, String[] returningAttributes)
    {
        try {
            for (String searchBase : searchBases) {
                processQuery(callback, searchBase, query, returningAttributes);
            }
        } finally {
            try {
                callback.close();
            } catch (NamingException e) {
            }
        }
    }

    /**
     * Invokes the given callback on each entry returned by the given query.
     *
     * @param callback
     *            the callback
     * @param searchBase
     *            the base DN for the search
     * @param query
     *            the query
     * @param returningAttributes
     *            the attributes to include in search results
     * @throws org.alfresco.error.AlfrescoRuntimeException
     */
    private void processQuery(SearchCallback callback, String searchBase, String query, String[] returningAttributes)
    {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(returningAttributes);
        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
        {
            LDAPMultiBaseUserRegistry.logger.debug("Processing query");
            LDAPMultiBaseUserRegistry.logger.debug("Search base: " + searchBase);
            LDAPMultiBaseUserRegistry.logger.debug("    Return result limit: " + searchControls.getCountLimit());
            LDAPMultiBaseUserRegistry.logger.debug("    DerefLink: " + searchControls.getDerefLinkFlag());
            LDAPMultiBaseUserRegistry.logger.debug("    Return named object: " + searchControls.getReturningObjFlag());
            LDAPMultiBaseUserRegistry.logger.debug("    Time limit for search: " + searchControls.getTimeLimit());
            LDAPMultiBaseUserRegistry.logger.debug("    Attributes to return: " + returningAttributes.length + " items.");
            for (String ra : returningAttributes)
            {
                LDAPMultiBaseUserRegistry.logger.debug("        Attribute: " + ra);
            }
        }
        InitialDirContext ctx = null;
        NamingEnumeration<SearchResult> searchResults = null;
        SearchResult result = null;
        try
        {
            ctx = this.ldapInitialContextFactory.getDefaultIntialDirContext(this.queryBatchSize);
            do
            {
                searchResults = ctx.search(searchBase, query, searchControls);

                while (searchResults.hasMore())
                {
                    result = searchResults.next();
                    callback.process(result);

                    // Close the contexts, see ALF-20682
                    Context resultCtx = (Context)result.getObject();
                    if(resultCtx != null)
                    {
                        resultCtx.close();
                    }
                    result = null;
                }
            }
            while (this.ldapInitialContextFactory.hasNextPage(ctx, this.queryBatchSize));
        }
        catch (NamingException e)
        {
            Object[] params = {e.getLocalizedMessage()};
            throw new AlfrescoRuntimeException("synchronization.err.ldap.search", params, e);
        }
        catch (ParseException e)
        {
            Object[] params = {e.getLocalizedMessage()};
            throw new AlfrescoRuntimeException("synchronization.err.ldap.search", params, e);
        }
        finally
        {
            if (result != null)
            {
                try
                {
                    Context resultCtx = (Context)result.getObject();
                    if(resultCtx != null)
                    {
                        resultCtx.close();
                    }
                }
                catch (Exception e)
                {
                    logger.debug("error when closing result block context", e);
                }
            }
            if (searchResults != null)
            {
                try
                {
                    searchResults.close();
                }
                catch (Exception e)
                {
                    logger.debug("error when closing searchResults context", e);
                }
            }
            if (ctx != null)
            {
                try
                {
                    ctx.close();
                }
                catch (NamingException e)
                {
                }
            }
        }
    }

    /**
     * Does a case-insensitive search for the given value in an attribute.
     *
     * @param attribute
     *            the attribute
     * @param value
     *            the value to search for
     * @return <code>true</code>, if the value was found
     * @throws javax.naming.NamingException
     *             if there is a problem accessing the attribute values
     */
    private boolean hasAttributeValue(Attribute attribute, String value) throws NamingException
    {
        if (attribute != null)
        {
            NamingEnumeration<?> values = attribute.getAll();
            while (values.hasMore())
            {
                try
                {
                    if (value.equalsIgnoreCase((String) values.next()))
                    {
                        return true;
                    }
                }
                catch (ClassCastException e)
                {
                    // Not a string value. ignore and continue
                }
            }
        }
        return false;
    }

    /**
     * Gets the values of a repeating attribute that may have range restriction options. If an attribute is range
     * restricted, it will appear in the attribute set with a ";range=i-j" option, where i and j indicate the start and
     * end index, and j is '*' if it is at the end.
     *
     * @param attributes
     *            the attributes
     * @param attributeName
     *            the attribute name
     * @return the range restricted attribute
     * @throws javax.naming.NamingException
     *             the naming exception
     */
    private Attribute getRangeRestrictedAttribute(Attributes attributes, String attributeName) throws NamingException
    {
        Attribute unrestricted = attributes.get(attributeName);
        if (unrestricted != null)
        {
            return unrestricted;
        }
        NamingEnumeration<? extends Attribute> i = attributes.getAll();
        String searchString = attributeName.toLowerCase() + ';';
        while (i.hasMore())
        {
            Attribute attribute = i.next();
            if (attribute.getID().toLowerCase().startsWith(searchString))
            {
                return attribute;
            }
        }
        return null;
    }

    /**
     * Wraps the LDAP user query as a virtual {@link java.util.Collection}.
     */
    public class PersonCollection extends AbstractCollection<NodeDescription>
    {

        /** The query. */
        private String query;

        /** The total estimated size. */
        private int totalEstimatedSize;

        /**
         * Instantiates a new person collection.
         *
         * @param modifiedSince
         *            if non-null, then only descriptions of users modified since this date should be returned; if
         *            <code>null</code> then descriptions of all users should be returned.
         */
        public PersonCollection(Date modifiedSince)
        {
            // Choose / generate the appropriate query
            if (modifiedSince == null)
            {
                this.query = LDAPMultiBaseUserRegistry.this.personQuery;
            }
            else
            {
                this.query = MessageFormat.format(LDAPMultiBaseUserRegistry.this.personDifferentialQuery,
                        LDAPMultiBaseUserRegistry.this.timestampFormat.format(modifiedSince));
            }

            // Estimate the size of this collection by running the entire query once, if progress
            // estimation is enabled
            if (LDAPMultiBaseUserRegistry.this.enableProgressEstimation)
            {
                class CountingCallback implements SearchCallback
                {
                    int count;

                    /*
                     * (non-Javadoc)
                     * @see
                     * org.alfresco.repo.security.sync.ldap.LDAPMultiBaseUserRegistry.SearchCallback#process(javax.naming.directory
                     * .SearchResult)
                     */
                    public void process(SearchResult result) throws NamingException, ParseException
                    {
                        this.count++;
                        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                        {
                            String personName = result.getNameInNamespace();
                            LDAPMultiBaseUserRegistry.logger.debug("Processing person: " + personName);
                        }
                    }

                    /*
                     * (non-Javadoc)
                     * @see org.alfresco.repo.security.sync.ldap.LDAPMultiBaseUserRegistry.SearchCallback#close()
                     */
                    public void close() throws NamingException
                    {
                    }

                }
                CountingCallback countingCallback = new CountingCallback();
                processQuery(countingCallback, LDAPMultiBaseUserRegistry.this.userSearchBases, this.query, new String[] {});
                this.totalEstimatedSize = countingCallback.count;
            }
            else
            {
                this.totalEstimatedSize = -1;
            }
        }

        /*
         * (non-Javadoc)
         * @see java.util.AbstractCollection#iterator()
         */
        @Override
        public Iterator<NodeDescription> iterator()
        {
            return new PersonIterator();
        }

        /*
         * (non-Javadoc)
         * @see java.util.AbstractCollection#size()
         */
        @Override
        public int size()
        {
            return this.totalEstimatedSize;
        }

        /**
         * An iterator over the person collection. Wraps the LDAP query in 'real time'.
         */
        private class PersonIterator implements Iterator<NodeDescription>
        {

            /** The directory context. */
            private InitialDirContext ctx;

            /** The user search controls. */
            private SearchControls userSearchCtls;

            /** The search results. */
            private NamingEnumeration<SearchResult> searchResults;

            private int searchBaseIndex = 0;

            /** The uids. */
            private HashSet<String> uids = new HashSet<String>();

            /** The next node description to return. */
            private NodeDescription next;

            /**
             * Instantiates a new person iterator.
             */
            public PersonIterator()
            {
                try
                {

                    this.ctx = LDAPMultiBaseUserRegistry.this.ldapInitialContextFactory
                            .getDefaultIntialDirContext(LDAPMultiBaseUserRegistry.this.queryBatchSize);

                    this.userSearchCtls = new SearchControls();
                    this.userSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    this.userSearchCtls.setReturningAttributes(LDAPMultiBaseUserRegistry.this.userKeys.getFirst());

                    this.next = fetchNext();
                }
                catch (NamingException e)
                {
                    throw new AlfrescoRuntimeException("Failed to import people.", e);
                }
                finally
                {
                    if (this.searchResults == null)
                    {
                        try
                        {
                            this.ctx.close();
                        }
                        catch (Exception e)
                        {
                        }
                        this.ctx = null;
                    }
                }
            }

            /*
             * (non-Javadoc)
             * @see java.util.Iterator#hasNext()
             */
            public boolean hasNext()
            {
                return this.next != null;
            }

            /*
             * (non-Javadoc)
             * @see java.util.Iterator#next()
             */
            public NodeDescription next()
            {
                if (this.next == null)
                {
                    throw new IllegalStateException();
                }
                NodeDescription current = this.next;
                try
                {
                    this.next = fetchNext();
                }
                catch (NamingException e)
                {
                    throw new AlfrescoRuntimeException("Failed to import people.", e);
                }
                return current;
            }

            /**
             * Pre-fetches the next node description to be returned.
             *
             * @return the node description
             * @throws javax.naming.NamingException
             *             on a naming exception
             */
            private NodeDescription fetchNext() throws NamingException
            {
                boolean readyForNextPage;
                do
                {
                    readyForNextPage = this.searchResults == null;
                    while (!readyForNextPage && this.searchResults.hasMore())
                    {
                        SearchResult result = this.searchResults.next();
                        Attributes attributes = result.getAttributes();
                        Attribute uidAttribute = attributes.get(LDAPMultiBaseUserRegistry.this.userIdAttributeName);
                        if (uidAttribute == null)
                        {
                            if (LDAPMultiBaseUserRegistry.this.errorOnMissingUID)
                            {
                                Object[] params = {result.getNameInNamespace(), LDAPMultiBaseUserRegistry.this.userIdAttributeName};
                                throw new AlfrescoRuntimeException("synchronization.err.ldap.get.user.id.missing", params);
                            }
                            else
                            {
                                LDAPMultiBaseUserRegistry.logger
                                        .warn("User returned by user search does not have mandatory user id attribute "
                                                + attributes);
                                continue;
                            }
                        }
                        String uid = (String) uidAttribute.get(0);

                        if (this.uids.contains(uid))
                        {
                            LDAPMultiBaseUserRegistry.logger
                                    .warn("Duplicate uid found - there will be more than one person object for this user - "
                                            + uid);
                        }

                        this.uids.add(uid);

                        if (LDAPMultiBaseUserRegistry.logger.isDebugEnabled())
                        {
                            LDAPMultiBaseUserRegistry.logger.debug("Adding user for " + uid);
                        }

                        // Apply the mapped properties to the node description
                        return mapToNode(LDAPMultiBaseUserRegistry.this.personAttributeMapping,
                                LDAPMultiBaseUserRegistry.this.personAttributeDefaults, result);
                    }

                    // Examine the paged results control response for an indication that another page is available
                    if (!readyForNextPage)
                    {
                        readyForNextPage = LDAPMultiBaseUserRegistry.this.ldapInitialContextFactory.hasNextPage(this.ctx,
                                LDAPMultiBaseUserRegistry.this.queryBatchSize);
                    }

                    // Fetch the next page if there is one
                    if (readyForNextPage)
                    {
                        this.searchResults = this.ctx.search
                                (LDAPMultiBaseUserRegistry.this.userSearchBases[this.searchBaseIndex],
                                PersonCollection.this.query, this.userSearchCtls);
                    }
                }
                while (readyForNextPage);
                this.searchResults.close();
                this.searchResults = null;

                this.ctx.close();
                this.ctx = null;

                // Additional logic to iterate through all search bases
                this.searchBaseIndex++;
                if (this.searchBaseIndex < LDAPMultiBaseUserRegistry.this.userSearchBases.length) {
                    this.ctx = LDAPMultiBaseUserRegistry.this.ldapInitialContextFactory
                            .getDefaultIntialDirContext(LDAPMultiBaseUserRegistry.this.queryBatchSize);
                    this.searchResults = this.ctx.search
                            (LDAPMultiBaseUserRegistry.this.userSearchBases[this.searchBaseIndex],
                                    PersonCollection.this.query, this.userSearchCtls);
                    return this.fetchNext();
                }

                return null;
            }

            /*
             * (non-Javadoc)
             * @see java.util.Iterator#remove()
             */
            public void remove()
            {
                throw new UnsupportedOperationException();
            }
        };
    }

    /**
     * An interface for callbacks passed to the
     * {@link LDAPMultiBaseUserRegistry#processQuery(SearchCallback, String, String, String[])} method.
     */
    protected static interface SearchCallback
    {

        /**
         * Processes the given search result.
         *
         * @param result
         *            the result
         * @throws javax.naming.NamingException
         *             on naming exceptions
         * @throws java.text.ParseException
         *             on parse exceptions
         */
        public void process(SearchResult result) throws NamingException, ParseException;

        /**
         * Release any resources held by the callback.
         *
         * @throws javax.naming.NamingException
         *             the naming exception
         */
        public void close() throws NamingException;
    }

}
