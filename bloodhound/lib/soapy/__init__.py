"""
SoaPy - Active Directory Web Services (ADWS) Protocol Implementation

This module provides Python implementations of the Microsoft protocols required
for interaction with ADWS (port 9389):
- MS-NNS: .NET NegotiateStream Protocol
- MC-NMF: .NET Message Framing Protocol
- MC-NBFSE: .NET Binary Format SOAP Extension

Based on SoaPy by IBM X-Force Red.
Modified for BloodHound.py - NTLM and Kerberos authentication.
"""

from .ms_nmf import NMFConnection
from .ms_nns import NNS
from .encoder import Encoder
from .adws import ADWSConnect, NTLMAuth, KerberosAuth, ADWSAuthType
from .soap_templates import NAMESPACES

__all__ = [
    "NMFConnection",
    "NNS",
    "Encoder",
    "ADWSConnect",
    "NTLMAuth",
    "KerberosAuth",
    "ADWSAuthType",
    "NAMESPACES",
]
