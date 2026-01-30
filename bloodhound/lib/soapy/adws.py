"""
ADWS (Active Directory Web Services) client implementation.

Modified for BloodHound.py - NTLM authentication only.
"""

import datetime
import logging
import socket
from base64 import b64decode
from enum import IntFlag
from typing import Self, Type
from uuid import UUID, uuid4
from xml.etree import ElementTree

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
    SYSTEM_MANDATORY_LABEL_ACE,
)
from pyasn1.type.useful import GeneralizedTime

from . import ms_nmf
from .ms_nns import NNS

from .soap_templates import (
    LDAP_PULL_FSTRING,
    LDAP_PUT_FSTRING,
    LDAP_QUERY_FSTRING,
    NAMESPACES,
)


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags
class SystemFlags(IntFlag):
    NONE = 0x00000000
    NO_REPLICATION = 0x00000001
    REPLICATE_TO_GC = 0x00000002
    CONSTRUCTED = 0x00000004
    CATEGORY_1 = 0x00000010
    NOT_DELETED = 0x02000000
    CANNOT_MOVE = 0x04000000
    CANNOT_RENAME = 0x08000000
    MOVED_WITH_RESTRICTIONS = 0x10000000
    MOVED = 0x20000000
    RENAMED = 0x40000000
    CANNOT_DELETE = 0x80000000


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
class InstanceTypeFlags(IntFlag):
    HEAD_OF_NAMING_CONTEXT = 0x00000001
    REPLICA_NOT_INSTANTIATED = 0x00000002
    OBJECT_WRITABLE = 0x00000004
    NAMING_CONTEXT_HELD = 0x00000008
    CONSTRUCTING_NAMING_CONTEXT = 0x00000010
    REMOVING_NAMING_CONTEXT = 0x00000020


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype
class GroupTypeFlags(IntFlag):
    SYSTEM_GROUP = 0x00000001
    GLOBAL_SCOPE = 0x00000002
    DOMAIN_LOCAL_SCOPE = 0x00000004
    UNIVERSAL_SCOPE = 0x00000008
    APP_BASIC_GROUP = 0x00000010
    APP_QUERY_GROUP = 0x00000020
    SECURITY_GROUP = 0x80000000


# https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
class AccountPropertyFlag(IntFlag):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


class SamAccountType(IntFlag):
    SAM_DOMAIN_OBJECT = 0x00000000
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001


BUILT_IN_GROUPS = {
    "498": "Enterprise Read-Only Domain Controllers",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "522": "Cloneable Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}

WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority",
    "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}


class ADWSError(Exception): ...


class ADWSAuthType: ...


class NTLMAuth(ADWSAuthType):
    def __init__(self, password: str | None = None, hashes: str | None = None):
        if not (password or hashes):
            raise ValueError("NTLM auth requires either a password or hashes.")

        if password and hashes:
            raise ValueError("Provide either a password or hashes, not both.")

        if hashes:
            self.nt = hashes
        else:
            self.nt = None

        self.password = password


class ADWSConnect:
    def __init__(
        self,
        fqdn: str,
        domain: str,
        username: str,
        auth: NTLMAuth,
        resource: str,
    ):
        """Creates an ADWS client connection to the specified endpoint.

        Args:
            fqdn: fqdn of the domain controller the ADWS service is running on
            domain: the domain
            username: user to auth as
            auth: auth mechanism to use (NTLMAuth)
            resource: the resource dictates what endpoint the client connects to
        """
        self._fqdn = fqdn
        self._domain = domain
        self._username = username
        self._auth = auth

        self._resource: str = resource

        self._nmf: ms_nmf.NMFConnection = self._connect(self._fqdn, self._resource)

    def _create_NNS_from_auth(self, sock: socket.socket) -> NNS:
        if isinstance(self._auth, NTLMAuth):
            return NNS(
                socket=sock,
                fqdn=self._fqdn,
                domain=self._domain,
                username=self._username,
                password=self._auth.password,
                nt=self._auth.nt if self._auth.nt else "",
            )
        raise NotImplementedError(f"Unsupported auth type: {type(self._auth)}")

    def _connect(self, remoteName: str, resource: str) -> ms_nmf.NMFConnection:
        """Connect to the specified ADWS endpoint."""
        server_address: tuple[str, int] = (remoteName, 9389)
        logging.debug(f"Connecting to ADWS at {remoteName}:9389 for {self._resource}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)

        nmf = ms_nmf.NMFConnection(
            self._create_NNS_from_auth(sock),
            fqdn=remoteName,
        )

        nmf.connect(f"Windows/{resource}")

        return nmf

    def _query_enumeration(
        self, remoteName: str, nmf: ms_nmf.NMFConnection, query: str, attributes: list,
        search_base: str | None = None
    ) -> str | None:
        """Send the query and set up an enumeration context for the results."""
        fAttributes: str = ""
        for attr in attributes:
            fAttributes += (
                "<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n".format(
                    attr=attr
                )
            )

        if search_base is None:
            search_base = ",".join([f"DC={i}" for i in self._domain.split(".")])

        query_vars = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
            "query": query,
            "attributes": fAttributes,
            "baseobj": search_base,
        }

        enumeration = LDAP_QUERY_FSTRING.format(**query_vars)

        nmf.send(enumeration)
        enumerationResponse = nmf.recv()

        et = self._handle_str_to_xml(enumerationResponse)
        if not et:
            raise ValueError("was unable to parse xml from the server response")

        enum_ctx = et.find(".//wsen:EnumerationContext", NAMESPACES)

        return enum_ctx.text if enum_ctx is not None else None

    def _pull_results(
        self, remoteName: str, nmf: ms_nmf.NMFConnection, enum_ctx: str
    ) -> tuple[ElementTree.Element, bool]:
        """Pull the results of an enumeration ctx from server."""
        pull_vars = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
            "enum_ctx": enum_ctx,
        }

        pull = LDAP_PULL_FSTRING.format(**pull_vars)
        nmf.send(pull)
        pullResponse = nmf.recv()

        et = self._handle_str_to_xml(pullResponse)
        if not et:
            raise ValueError("was unable to parse xml from the server response")

        final_pkt = et.find(".//wsen:EndOfSequence", namespaces=NAMESPACES)
        if final_pkt is not None:
            return (et, False)

        return (et, True)

    def _handle_str_to_xml(self, xmlstr: str) -> ElementTree.Element | None:
        """Takes an xml string and returns an Element of the root node."""
        if ":Fault>" not in xmlstr and ":Reason>" not in xmlstr:
            return ElementTree.fromstring(xmlstr)

        def manually_cut_out_fault(xml_str: str) -> str:
            starttag = xml_str.find(":Text") + len(":Text")
            endtag = xml_str[starttag:].find(":Text")
            return xml_str[starttag : starttag + endtag]

        et: ElementTree.Element | None = None
        try:
            et = ElementTree.fromstring(xmlstr)
        except ElementTree.ParseError:
            msg = manually_cut_out_fault(xmlstr)
            raise ADWSError(msg)

        base_msg = str()

        fault = et.find(".//soapenv:Fault", namespaces=NAMESPACES)
        if not fault:
            return et

        reason = fault.find(".//soapenv:Text", namespaces=NAMESPACES)
        base_msg += reason.text if reason is not None else ""

        detail = fault.find(".//soapenv:Detail", namespaces=NAMESPACES)
        if detail is not None:
            ElementTree.indent(detail)
            detail_xmlstr = (
                ElementTree.tostring(detail, encoding="unicode")
                if detail is not None
                else ""
            )
        else:
            detail_xmlstr = ""

        raise ADWSError(base_msg + detail_xmlstr)

    def _get_tag_name(self, elem: ElementTree.Element) -> str:
        return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

    def put(
        self,
        object_ref: str,
        operation: str,
        attribute: str,
        data_type: str,
        value: str,
    ) -> bool:
        """CRUD on attribute."""
        if self._resource != "Resource":
            raise NotImplementedError("Put is only supported on 'put' clients")

        put_vars = {
            "object_ref": object_ref,
            "uuid": str(uuid4()),
            "fqdn": self._fqdn,
            "operation": operation,
            "attribute": attribute,
            "data_type": data_type,
            "value": value,
        }

        put_msg = LDAP_PUT_FSTRING.format(**put_vars)

        self._nmf.send(put_msg)
        resp_str = self._nmf.recv()
        et = self._handle_str_to_xml(resp_str)
        if not et:
            raise ValueError("was unable to parse xml from the server response")

        body = et.find(".//soapenv:Body", namespaces=NAMESPACES)

        return (
            body is None
            or len(body) == 0
            and (body.text is None or body.text.strip() == "")
        )

    def pull(
        self,
        query: str,
        attributes: list,
        search_base: str | None = None,
        print_incrementally: bool = False,
    ) -> ElementTree.Element:
        """Makes an LDAP query using ADWS to the specified server."""
        if self._resource != "Enumeration":
            raise NotImplementedError("Pull is only supported on 'pull' clients")

        enum_ctx = self._query_enumeration(
            remoteName=self._fqdn,
            nmf=self._nmf,
            query=query,
            attributes=attributes,
            search_base=search_base,
        )
        if enum_ctx is None:
            logging.error(
                "Server did not return an enumeration context in response to making a query"
            )
            raise ValueError("unable to get enumeration context")

        ElementTree.register_namespace("wsen", NAMESPACES["wsen"])
        results: ElementTree.Element = ElementTree.Element("wsen:Items")
        more_results = True
        while more_results:
            et, more_results = self._pull_results(
                remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
            )
            if len(et.findall(".//wsen:Items", namespaces=NAMESPACES)) == 0:
                logging.debug("No objects returned in this batch")
            else:
                for item in et.findall(".//wsen:Items", namespaces=NAMESPACES):
                    results.append(item)

        return results

    @classmethod
    def pull_client(cls, ip: str, domain: str, username: str, auth: NTLMAuth) -> Self:
        return cls(ip, domain, username, auth, "Enumeration")

    @classmethod
    def put_client(cls, ip: str, domain: str, username: str, auth: NTLMAuth) -> Self:
        return cls(ip, domain, username, auth, "Resource")
