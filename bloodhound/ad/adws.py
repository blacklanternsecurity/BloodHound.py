"""
ADWS (Active Directory Web Services) client for BloodHound.py

This module provides an ADWSClient class that wraps the low-level ADWS protocol
implementation and provides an ldap3-compatible interface for BloodHound's
enumeration code.
"""

import logging
import re
import threading
from base64 import b64decode
from datetime import datetime
from typing import Any, Dict, List, Optional, Generator
from uuid import UUID
from xml.etree import ElementTree

from ldap3.utils.ciDict import CaseInsensitiveDict

from bloodhound.lib.soapy import ADWSConnect, NTLMAuth, KerberosAuth, NAMESPACES
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

    # Attributes that should be converted to integers (ADWS returns strings).
    # Includes FILETIME-style attributes (100-ns intervals since 1601) that
    # downstream code feeds into ADUtils.win_timestamp_to_unix as ints.
    INTEGER_ATTRIBUTES = {
        "userAccountControl",
        "systemFlags",
        "sAMAccountType",
        "groupType",
        "primaryGroupID",
        "instanceType",
        "msDS-SupportedEncryptionTypes",
        "msDS-Behavior-Version",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "searchFlags",
        "adminCount",
        "logonCount",
        "badPwdCount",
        # FILETIME-valued attributes
        "lastLogon",
        "lastLogonTimestamp",
        "pwdLastSet",
        "accountExpires",
        "badPasswordTime",
        "lockoutTime",
        "lastLogoff",
    }

    # Attributes ADWS returns as directory timestamps. The on-wire format
    # varies: some servers emit GeneralizedTime ("20260501201908.0Z") while
    # others emit XSD dateTime ("2026-05-01T20:19:08.0000000Z"). ldap3 parses
    # both into Python datetime objects, and BloodHound's enumeration code
    # calls .timetuple() on them, so we match that behavior here.
    DATETIME_ATTRIBUTES = {
        "whenCreated",
        "whenChanged",
    }
    # Lower-cased view used for case-insensitive attribute-name matching.
    _DATETIME_ATTRIBUTES_LOWER = {a.lower() for a in DATETIME_ATTRIBUTES}

    @staticmethod
    def _parse_ad_datetime(value: str) -> Optional[datetime]:
        """Parse AD GeneralizedTime or XSD dateTime into a datetime.

        Returns None if the input cannot be parsed in either format.
        """
        from datetime import timezone
        s = value.strip()
        # Try XSD dateTime first (contains separators)
        if '-' in s or 'T' in s:
            try:
                return datetime.fromisoformat(s.replace('Z', '+00:00'))
            except ValueError:
                pass
        # Try GeneralizedTime: YYYYMMDDHHMMSS[.f]Z or YYYYMMDDHHMMSSZ
        core = s.rstrip('Z').split('.')[0]
        try:
            return datetime.strptime(core, '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def __init__(self, hostname: str, ad: "AD", target_ip: str | None = None):
        """
        Initialize ADWS client.

        Args:
            hostname: DC FQDN for SPN construction and NMF via
            ad: BloodHound AD object containing auth and domain info
            target_ip: Resolved IP for TCP connection (uses hostname if not set)
        """
        self.hostname = hostname
        self.target_ip = target_ip
        self.ad = ad
        self._client: Optional[ADWSConnect] = None
        self._schema_classes: Optional[set] = None
        self._configuration_dn: Optional[str] = None
        # Serializes SOAP request/response cycles on the single shared TCP/NMF
        # stream. Without this, the main enumeration thread and the ACL
        # callback thread (from the multiprocessing pool's result callback)
        # can interleave requests, corrupting frames and causing server RST.
        self._io_lock = threading.Lock()

    def connect(self) -> None:
        """
        Connect to ADWS on port 9389.

        Raises:
            CollectionException: If connection fails
        """
        self._create_connection()
        self._resolve_base_dn()

    def _create_connection(self) -> None:
        """Establish the underlying ADWS TCP/NMF connection."""
        auth = self.ad.auth

        # Prefer Kerberos if TGT is available
        if auth.tgt is not None:
            adws_auth = KerberosAuth(
                tgt=auth.tgt,
                domain=auth.domain,
                kdc=auth.kdc,
            )
        elif auth.nt_hash:
            adws_auth = NTLMAuth(hashes=auth.nt_hash)
        elif auth.password:
            adws_auth = NTLMAuth(password=auth.password)
        else:
            raise CollectionException("ADWS requires password, NT hash, or Kerberos TGT for authentication")

        try:
            logging.debug('Connecting to ADWS server: %s', self.hostname)
            self._client = ADWSConnect.pull_client(
                ip=self.hostname,
                domain=self.ad.domain,
                username=auth.username,
                auth=adws_auth,
                target_ip=self.target_ip,
            )
            logging.debug('Successfully connected to ADWS')
        except Exception as e:
            self._client = None
            logging.error('ADWS connection failed: %s', str(e))
            raise CollectionException(f'ADWS connection failed: {e}. No LDAP fallback in ADWS mode.')

    def _reconnect(self) -> bool:
        """Attempt to re-establish a dropped ADWS connection."""
        self._client = None
        try:
            logging.info('ADWS connection lost, reconnecting...')
            self._create_connection()
            logging.info('ADWS reconnected successfully')
            return True
        except Exception as e:
            logging.warning('ADWS reconnection failed: %s', e)
            return False

    @staticmethod
    def _is_transient_error(exc: Exception) -> bool:
        """Check if an ADWS error is a transient connection failure."""
        msg = str(exc).lower()
        return any(s in msg for s in (
            'noconnectionavailable',
            'no connection',
            'connection reset',
            'connection refused',
            'broken pipe',
            'timed out',
        ))

    def _resolve_base_dn(self) -> None:
        """Resolve the correct base DN and configuration partition DN.

        ADWS is case-sensitive about distinguished names unlike LDAP. The
        base DN we construct from DNS is lowercased, but the server may
        store it with mixed case. A probe search lets the server tell us
        the real DN — either via a successful result or via MatchedDN in
        the SOAP fault.

        The Configuration partition lives at the forest root, not the
        domain root, so for child domains we also need to discover the
        real configuration DN rather than assuming it's under our baseDN.
        """
        self.ad.baseDN = self._probe_dn(self.ad.baseDN)
        self._resolve_configuration_dn()

    def _probe_dn(self, dn: str) -> str:
        """Search for a DN and return the server's correctly-cased version."""
        try:
            with self._io_lock:
                results_xml = self._client.pull(
                    query="(objectClass=*)",
                    attributes=["distinguishedName"],
                    search_base=dn,
                    scope="Base",
                )
            for entry in self._parse_xml_entries(results_xml):
                result_dn = entry.get('dn') or entry.get('attributes', {}).get('distinguishedName')
                if result_dn:
                    if isinstance(result_dn, list):
                        result_dn = result_dn[0]
                    if result_dn != dn:
                        logging.debug('Corrected DN casing: %s -> %s', dn, result_dn)
                    return result_dn
                break
        except Exception as e:
            error_str = str(e)
            match = re.search(r'<\w+:MatchedDN>([^<]+)</\w+:MatchedDN>', error_str)
            if match:
                matched_dn = match.group(1)
                if matched_dn.upper() == dn.upper():
                    logging.debug('Corrected DN casing from MatchedDN: %s -> %s', dn, matched_dn)
                    return matched_dn
            logging.debug('Could not resolve DN casing for %s: %s', dn, e)
        return dn

    def _resolve_configuration_dn(self) -> None:
        """Discover the Configuration partition DN.

        In a child domain the Configuration partition is at the forest
        root (e.g. CN=Configuration,DC=Forest,DC=com), not under the
        child domain DN. We walk up the DC components until we find a
        Configuration container that exists.
        """
        dc_parts = [p for p in self.ad.baseDN.split(',') if p.upper().startswith('DC=')]
        for i in range(len(dc_parts)):
            candidate_root = ','.join(dc_parts[i:])
            candidate = f"CN=Configuration,{candidate_root}"
            try:
                with self._io_lock:
                    self._client.pull(
                        query="(objectClass=*)",
                        attributes=["distinguishedName"],
                        search_base=candidate,
                        scope="Base",
                    )
                self._configuration_dn = candidate
                if i > 0:
                    logging.debug('Found Configuration partition at forest root: %s', candidate)
                return
            except Exception:
                continue
        logging.debug('Could not discover Configuration partition, using default')

    @property
    def configuration_naming_context(self) -> str:
        """Return configuration partition base DN."""
        if self._configuration_dn:
            return self._configuration_dn
        return f"CN=Configuration,{self.ad.baseDN}"

    @property
    def schema_naming_context(self) -> str:
        """Return schema partition base DN."""
        return f"CN=Schema,{self.configuration_naming_context}"

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
            with self._io_lock:
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

    # Map from ldap3 search scope constants to ADWS LdapQuery dialect scope strings.
    # ldap3 exposes these as strings: 'BASE', 'LEVEL', 'SUBTREE'.
    _SCOPE_MAP = {
        'BASE': 'Base',
        'LEVEL': 'OneLevel',
        'SUBTREE': 'Subtree',
    }

    def search(
        self,
        search_filter: str,
        attributes: Optional[List[str]] = None,
        search_base: Optional[str] = None,
        query_sd: bool = False,
        search_scope: str = 'SUBTREE',
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Search via ADWS, yielding ldap3-compatible entries.

        Args:
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve
            search_base: Base DN for search (defaults to domain base)
            query_sd: Whether to query security descriptors
            search_scope: ldap3 scope constant ('BASE', 'LEVEL', or 'SUBTREE')

        Yields:
            Dict entries in ldap3 format: {'type': 'searchResEntry', 'dn': ..., 'attributes': ...}
        """
        if self._client is None:
            self.connect()

        if not search_base:  # Handle None and empty string
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

        adws_scope = self._SCOPE_MAP.get(str(search_scope).upper(), 'Subtree')

        for attempt in range(2):
            try:
                with self._io_lock:
                    results_xml = self._client.pull(
                        query=search_filter,
                        attributes=attr_list,
                        search_base=search_base,
                        scope=adws_scope,
                        query_sd=query_sd,
                    )

                for entry in self._parse_xml_entries(results_xml):
                    yield entry
                return

            except Exception as e:
                if attempt == 0 and self._is_transient_error(e) and self._reconnect():
                    continue
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

        for attempt in range(2):
            try:
                with self._io_lock:
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
                if attempt == 0 and self._is_transient_error(e) and self._reconnect():
                    continue
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
        # CaseInsensitiveDict matches ldap3's behavior. ADWS returns
        # attribute names in their schema casing (e.g. "whenCreated"),
        # but downstream enumeration code looks them up in mixed casing
        # ("whencreated", "lastLogon", etc.). Without case-insensitive
        # lookup, those reads silently fall back to defaults.
        attributes: CaseInsensitiveDict = CaseInsensitiveDict()
        raw_attributes: CaseInsensitiveDict = CaseInsensitiveDict()
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

            # Parse directory timestamp strings into Python datetime objects.
            # ldap3 returns datetimes for these, and BloodHound's property code
            # (memberships.py) calls .timetuple() on them. ADWS can return
            # either GeneralizedTime ("20260501201908.0Z") or XSD dateTime
            # ("2026-05-01T20:19:08.0000000Z"); handle both.
            elif attr_name.lower() in self._DATETIME_ATTRIBUTES_LOWER:
                parsed: list = []
                ok = True
                for v in values:
                    dt = self._parse_ad_datetime(v)
                    if dt is None:
                        ok = False
                        break
                    parsed.append(dt)
                if ok:
                    values = parsed
                raw_values = [v.encode("utf-8") if isinstance(v, str) else v for v in raw_values]

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
