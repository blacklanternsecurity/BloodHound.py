"""
ADWS (Active Directory Web Services) client for BloodHound.py

This module provides an ADWSClient class that wraps the low-level ADWS protocol
implementation and provides an ldap3-compatible interface for BloodHound's
enumeration code.
"""

import logging
from base64 import b64decode
from typing import Any, Dict, List, Optional, Generator
from uuid import UUID
from xml.etree import ElementTree

from bloodhound.lib.soapy import ADWSConnect, NTLMAuth, NAMESPACES
from bloodhound.ad.utils import CollectionException
from impacket.ldap.ldaptypes import LDAP_SID


class ADWSClient:
    """
    ADWS client that provides ldap3-compatible interface for BloodHound.py.

    This class wraps the low-level ADWSConnect class and provides methods
    that return data in the same format as ldap3, allowing it to be used
    as a drop-in replacement for LDAP enumeration.
    """

    # Binary attributes that need base64 decoding
    BINARY_ATTRIBUTES = {
        "cACertificate",
        "userCertificate",
        "nTSecurityDescriptor",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "dnsRecord",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "logonHours",
        "schemaIDGUID",
        "attributeSecurityGUID",
        "msDS-GroupMSAMembership",
    }

    # Attributes that should always be stored as lists
    ARRAY_ATTRIBUTES = {
        "member",
        "memberOf",
        "msDS-AllowedToDelegateTo",
        "pKIExtendedKeyUsage",
        "servicePrincipalName",
        "certificateTemplates",
        "cACertificate",
        "sIDHistory",
        "objectClass",
    }

    # Attributes that should be converted to integers (ADWS returns strings)
    INTEGER_ATTRIBUTES = {
        "userAccountControl",
        "systemFlags",
        "sAMAccountType",
        "groupType",
        "primaryGroupID",
        "instanceType",
        "msDS-SupportedEncryptionTypes",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "searchFlags",
        "adminCount",
        "logonCount",
        "badPwdCount",
    }

    def __init__(self, hostname: str, ad: "AD"):
        """
        Initialize ADWS client.

        Args:
            hostname: DC hostname or IP to connect to
            ad: BloodHound AD object containing auth and domain info
        """
        self.hostname = hostname
        self.ad = ad
        self._client: Optional[ADWSConnect] = None
        self._schema_classes: Optional[set] = None

    def connect(self) -> None:
        """
        Connect to ADWS on port 9389.

        Raises:
            CollectionException: If connection fails
        """
        auth = self.ad.auth

        # Create NTLMAuth from BloodHound credentials
        if auth.nt_hash:
            adws_auth = NTLMAuth(hashes=auth.nt_hash)
        elif auth.password:
            adws_auth = NTLMAuth(password=auth.password)
        else:
            raise CollectionException("ADWS requires password or NT hash for authentication")

        try:
            logging.info('Connecting to ADWS server: %s', self.hostname)
            self._client = ADWSConnect.pull_client(
                ip=self.hostname,
                domain=self.ad.domain,
                username=auth.username,
                auth=adws_auth,
            )
            logging.info('Successfully connected to ADWS')
        except Exception as e:
            logging.error('ADWS connection failed: %s', str(e))
            raise CollectionException(f'ADWS connection failed: {e}. No LDAP fallback in ADWS mode.')

    @property
    def configuration_naming_context(self) -> str:
        """Return configuration partition base DN."""
        return f"CN=Configuration,{self.ad.baseDN}"

    @property
    def schema_naming_context(self) -> str:
        """Return schema partition base DN."""
        return f"CN=Schema,CN=Configuration,{self.ad.baseDN}"

    def supports_object_class(self, class_name: str) -> bool:
        """
        Check if schema supports the given object class.

        Args:
            class_name: Object class name to check (e.g., 'msDS-GroupManagedServiceAccount')

        Returns:
            True if object class exists in schema
        """
        if self._schema_classes is None:
            self._query_schema_classes()
        return class_name in self._schema_classes

    def _query_schema_classes(self) -> None:
        """Query schema to populate object class cache."""
        self._schema_classes = set()

        try:
            results = self._client.pull(
                query="(objectClass=classSchema)",
                attributes=["lDAPDisplayName"],
                search_base=self.schema_naming_context,
            )

            for entry in self._parse_xml_entries(results):
                name = entry['attributes'].get('lDAPDisplayName')
                if name:
                    self._schema_classes.add(name)

            logging.debug('Loaded %d schema classes from ADWS', len(self._schema_classes))
        except Exception as e:
            logging.warning('Failed to query schema classes: %s', e)
            # Provide common classes as fallback
            self._schema_classes = {
                'user', 'group', 'computer', 'organizationalUnit', 'container',
                'groupPolicyContainer', 'trustedDomain', 'domain',
                'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount'
            }

    def search(
        self,
        search_filter: str,
        attributes: Optional[List[str]] = None,
        search_base: Optional[str] = None,
        query_sd: bool = False,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Search via ADWS, yielding ldap3-compatible entries.

        Args:
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve
            search_base: Base DN for search (defaults to domain base)
            query_sd: Whether to query security descriptors

        Yields:
            Dict entries in ldap3 format: {'type': 'searchResEntry', 'dn': ..., 'attributes': ...}
        """
        if self._client is None:
            self.connect()

        if search_base is None:
            search_base = self.ad.baseDN

        # ADWS requires explicit attribute lists - provide minimal defaults if none specified
        if attributes is None or len(attributes) == 0:
            attr_list = ['distinguishedName', 'objectSid', 'objectClass']
        elif isinstance(attributes, str):
            attr_list = [attributes]
        else:
            attr_list = list(attributes)

        # Add nTSecurityDescriptor if query_sd requested
        if query_sd and "nTSecurityDescriptor" not in attr_list:
            attr_list.append("nTSecurityDescriptor")

        try:
            results_xml = self._client.pull(
                query=search_filter,
                attributes=attr_list,
                search_base=search_base,
            )

            for entry in self._parse_xml_entries(results_xml):
                yield entry

        except Exception as e:
            logging.warning('ADWS search %r failed: %s', search_filter, e)

    def get_single(
        self,
        dn: str,
        attributes: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Get a single object by DN.

        Args:
            dn: Distinguished name of object
            attributes: List of attributes to retrieve

        Returns:
            Entry dict or None if not found
        """
        if self._client is None:
            self.connect()

        # ADWS requires explicit attribute lists - provide minimal defaults if none specified
        if attributes is None or len(attributes) == 0:
            attr_list = ['distinguishedName', 'objectSid', 'objectClass']
        else:
            attr_list = list(attributes)

        try:
            # Use the DN as the search base with a simple filter
            results_xml = self._client.pull(
                query="(objectClass=*)",
                attributes=attr_list,
                search_base=dn,
            )

            entries = list(self._parse_xml_entries(results_xml))
            if entries:
                return entries[0]
            return None

        except Exception as e:
            logging.warning('ADWS get_single %r failed: %s', dn, e)
            return None

    def _parse_xml_entries(self, xml_root: ElementTree.Element) -> Generator[Dict[str, Any], None, None]:
        """
        Convert ADWS XML response to ldap3-compatible entries.

        Args:
            xml_root: Root XML element from ADWS response

        Yields:
            Entry dicts in ldap3 format
        """
        # Find all items in the response
        for items in xml_root.findall(".//wsen:Items", namespaces=NAMESPACES):
            for item in items:
                entry = self._parse_xml_item(item)
                if entry is not None:
                    yield entry

    def _parse_xml_item(self, item: ElementTree.Element) -> Optional[Dict[str, Any]]:
        """
        Parse a single ADWS XML item into ldap3 entry format.

        Args:
            item: XML element representing an AD object

        Returns:
            Entry dict or None if parsing fails
        """
        attributes: Dict[str, Any] = {}
        raw_attributes: Dict[str, Any] = {}
        dn = None

        for attr in item:
            attr_name = attr.tag.split("}")[-1] if "}" in attr.tag else attr.tag

            # Get all values for this attribute
            values = []
            raw_values = []

            # Try ad:value namespace
            value_elems = attr.findall(".//{http://schemas.microsoft.com/2008/1/ActiveDirectory}value")

            for value_elem in value_elems:
                text = value_elem.text
                if text is None:
                    text = "".join(value_elem.itertext())

                if text is not None and len(text) > 0:
                    values.append(text)
                    raw_values.append(text)

            if not values:
                continue

            # Handle special attribute types
            if attr_name == "distinguishedName":
                dn = values[0]

            # Convert SID attributes
            if attr_name in ["objectSid", "securityIdentifier"]:
                try:
                    decoded_values = []
                    for v in values:
                        sid = LDAP_SID(data=b64decode(v))
                        decoded_values.append(sid.formatCanonical())
                    values = decoded_values
                except Exception:
                    pass

            # Handle sIDHistory (array of SIDs)
            elif attr_name == "sIDHistory":
                try:
                    decoded_values = []
                    for v in values:
                        sid = LDAP_SID(data=b64decode(v))
                        decoded_values.append(sid.formatCanonical())
                    values = decoded_values
                    # Keep raw as binary for compatibility
                    raw_values = [b64decode(v) for v in raw_values]
                except Exception:
                    pass

            # Convert GUID attributes
            elif attr_name == "objectGUID":
                try:
                    decoded_values = []
                    for v in values:
                        guid = UUID(bytes_le=b64decode(v))
                        decoded_values.append("{" + str(guid) + "}")
                    values = decoded_values
                except Exception:
                    pass

            # Handle schemaIDGUID (binary GUID)
            elif attr_name == "schemaIDGUID":
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
                except Exception:
                    pass

            # Handle binary attributes
            elif attr_name in self.BINARY_ATTRIBUTES:
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
                except Exception:
                    pass

            # Convert integer attributes from string to int
            elif attr_name in self.INTEGER_ATTRIBUTES:
                try:
                    values = [int(v) for v in values]
                    raw_values = values
                except (ValueError, TypeError):
                    pass

            else:
                # For string attributes, raw_attributes should contain bytes
                raw_values = [v.encode("utf-8") if isinstance(v, str) else v for v in values]

            # Store single value or list based on count and attribute type
            if len(values) == 1 and attr_name not in self.ARRAY_ATTRIBUTES:
                attributes[attr_name] = values[0]
            else:
                attributes[attr_name] = values

            # Same logic for raw_attributes
            if len(raw_values) == 1 and attr_name not in self.ARRAY_ATTRIBUTES:
                raw_attributes[attr_name] = raw_values[0]
            else:
                raw_attributes[attr_name] = raw_values

        if not attributes:
            return None

        # Return in ldap3 format
        return {
            'type': 'searchResEntry',
            'dn': dn,
            'attributes': attributes,
            'raw_attributes': raw_attributes,
        }
