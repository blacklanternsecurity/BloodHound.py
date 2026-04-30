"""
ADWS (Active Directory Web Services) client for BloodHound.py

This module provides an ADWSClient class that wraps the low-level ADWS protocol
implementation and provides an ldap3-compatible interface for BloodHound's
enumeration code.
"""

import logging
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
        self._configuration_naming_context: Optional[str] = None
        self._schema_naming_context: Optional[str] = None
        self._config_nc_accessible: bool = False
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
            self._fetch_naming_contexts()
        except CollectionException:
            raise
        except Exception as e:
            logging.error('ADWS connection failed: %s', str(e))
            raise CollectionException(f'ADWS connection failed: {e}. No LDAP fallback in ADWS mode.')

    def _fetch_naming_contexts(self) -> None:
        """Probe the current domain's configuration NC and use it if accessible.

        Only the current domain base is probed.  Probing parent/forest-root paths
        triggers ADWS referral-following on the server side, which can leave the
        ADWS service unable to process subsequent domain NC queries.  A wrong-but-
        local path (error 32 / NO_OBJECT) is safe; a cross-partition referral is not.
        """
        candidate_config = f"CN=Configuration,{self.ad.baseDN}"
        partitions_dn = f"CN=Partitions,{candidate_config}"
        try:
            with self._io_lock:
                results_xml = self._client.pull(
                    query='(objectClass=crossRefContainer)',
                    attributes=['distinguishedName'],
                    search_base=partitions_dn,
                    scope='Base',
                )
            for _ in self._parse_xml_entries(results_xml):
                self._configuration_naming_context = candidate_config
                self._schema_naming_context = f"CN=Schema,{candidate_config}"
                self._config_nc_accessible = True
                logging.debug('Found configuration NC: %s', candidate_config)
                return
        except Exception as e:
            logging.debug('Config NC not found at %s: %s', candidate_config, e)

        # Config NC is not hosted by this DC (child domain DC pointing at forest root
        # config partition).  Keep using the constructed local path so all config NC
        # searches fail fast with NO_OBJECT rather than triggering referrals that
        # break the ADWS service for subsequent domain NC queries.
        logging.warning(
            'Configuration partition is not accessible via this DC; '
            'schema/trust/NetBIOS data will be unavailable. '
            'For full collection, connect to a forest root DC.'
        )
        self._configuration_naming_context = candidate_config
        self._schema_naming_context = f"CN=Schema,{candidate_config}"

    @property
    def configuration_naming_context(self) -> str:
        """Return configuration partition base DN."""
        if self._configuration_naming_context is not None:
            return self._configuration_naming_context
        return f"CN=Configuration,{self.ad.baseDN}"

    @property
    def schema_naming_context(self) -> str:
        """Return schema partition base DN."""
        if self._schema_naming_context is not None:
            return self._schema_naming_context
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
        if not self._config_nc_accessible:
            # Do NOT include GMSA/SMSA here. When the schema NC is inaccessible,
            # claiming support for these classes causes get_users() to build a
            # complex OR filter and get_computers() to build NOT filters.  Those
            # operators fail silently on child-domain DCs whose ADWS cannot reach
            # the forest-root schema NC, returning 0 objects instead of an error.
            self._schema_classes = {
                'user', 'group', 'computer', 'organizationalUnit', 'container',
                'groupPolicyContainer', 'trustedDomain', 'domain',
            }
            return

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

        # On child domain DCs the schema NC lives on the forest root.  Querying it
        # triggers server-side referral-following that leaves the ADWS service unable
        # to process any subsequent request (NoConnectionAvailable).  Skip silently.
        if not self._config_nc_accessible and 'cn=schema,' in search_base.lower():
            return

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

        try:
            # enumerate_batches() yields one XML batch (≤256 objects) per Pull
            # response.  The lock is held only for each individual Enumerate or
            # Pull round-trip so other threads (e.g. the ACL pool callback) can
            # interleave their own requests between batches.  Results are yielded
            # to the caller as each batch arrives rather than after the full
            # result set is buffered in memory.
            batch_gen = self._client.enumerate_batches(
                query=search_filter,
                attributes=attr_list,
                search_base=search_base,
                scope=adws_scope,
                query_sd=query_sd,
            )
            batch_num = 0
            total_yielded = 0
            while True:
                with self._io_lock:
                    try:
                        batch_et = next(batch_gen)
                    except StopIteration:
                        break
                    except Exception as e:
                        if batch_num == 0:
                            logging.warning('ADWS search %r failed: %s', search_filter, e)
                        else:
                            logging.warning(
                                'ADWS search %r truncated after %d objects (batch %d failed): %s',
                                search_filter, total_yielded, batch_num, e,
                            )
                        break
                batch_num += 1
                for entry in self._parse_xml_entries(batch_et):
                    total_yielded += 1
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
            # Use the DN as the search base with a simple filter.
            # See search() for the rationale on the I/O lock.
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

            # Handle sIDHistory - keep as raw bytes so downstream code
            # (memberships.py) can call LDAP_SID() on it, matching LDAP path behavior.
            elif attr_name == "sIDHistory":
                try:
                    raw_values = [b64decode(v) for v in values]
                    values = raw_values
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
