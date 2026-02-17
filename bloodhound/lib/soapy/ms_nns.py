"""
[MS-NNS]: .NET NegotiateStream Protocol

The .NET NegotiateStream Protocol provides mutually authenticated
and confidential communication over a TCP connection.

Supports both NTLM and Kerberos authentication.
"""

import datetime
import logging
import os
import socket
import struct

import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket.hresult_errors import ERROR_MESSAGES
from impacket.krb5 import constants as krb5_constants
from impacket.krb5 import gssapi as krb5_gssapi
from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.crypto import Key as KerberosKey
from impacket.krb5.gssapi import CheckSumField, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from .encoder.records.utils import Net7BitInteger


def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        # Kerberos parameters
        tgt: dict | None = None,
        domain_for_tgs: str | None = None,
        kdc: str | None = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0

        # Kerberos state
        self._tgt = tgt
        self._domain_for_tgs = domain_for_tgs or domain
        self._kdc = kdc or fqdn

        # Set _kerberos_target so NMF._upgrade() knows to call auth_kerberos()
        self._kerberos_target = fqdn if tgt is not None else None

        # GSS-API wrapper for Kerberos (None = NTLM mode)
        self._gss = None
        self._krb_session_key = None

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes
        """
        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context"""
        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Receive an NNS packet and return the entire decrypted contents."""
        first_pkt = self._recv()

        # if it isn't an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # it's all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()
            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Receive an NNS packet and return the entire decrypted contents."""
        size = int.from_bytes(self._sock.recv(4), "little")

        payload = b""
        while len(payload) != size:
            payload += self._sock.recv(size - len(payload))

        if self._gss is not None:
            # Kerberos: unwrap per-message token
            if self._krb_session_key.enctype == 23:  # RC4-HMAC
                clearText = self._rc4_unwrap(payload)
            else:  # AES
                clearText, _ = self._gss.GSS_Unwrap_LDAP(
                    self._krb_session_key, payload, self._recv_sequence
                )
            self._recv_sequence += 1
            return clearText
        else:
            # NTLM decryption
            nns_signed_payload = NNS_Signed_payload()
            nns_signed_payload["signature"] = payload[0:16]
            nns_signed_payload["cipherText"] = payload[16:]

            clearText, sig = self.seal(nns_signed_payload["cipherText"])
            return clearText

    def sendall(self, data: bytes):
        """send to server in sealed NNS data packet via tcp socket."""

        if self._gss is not None:
            # Kerberos: wrap per-message token
            if self._krb_session_key.enctype == 23:  # RC4-HMAC
                wrapped = self._rc4_wrap(data, self._sequence)
            else:  # AES
                cipherText, signature = self._gss.GSS_Wrap_LDAP(
                    self._krb_session_key, data, self._sequence,
                    direction='init', encrypt=True
                )
                wrapped = signature + cipherText

            pkt = NNS_data()
            pkt["payload"] = wrapped
            self._sock.sendall(pkt.getData())
        else:
            # NTLM encryption
            cipherText, sig = impacket.ntlm.SEAL(
                self._flags,
                self._client_signing_key,
                self._client_sealing_key,
                data,
                data,
                self._sequence,
                self._client_sealing_handle,
            )

            pkt = NNS_data()

            payload = NNS_Signed_payload()
            payload["signature"] = sig
            payload["cipherText"] = cipherText
            pkt["payload"] = payload.getData()

            self._sock.sendall(pkt.getData())

        # increment the sequence number after sending
        self._sequence += 1

    def _rc4_wrap(self, data, seq_num):
        """Wrap data using RFC 4757 RC4-HMAC (bare mechanism token, no MechIndepToken).

        Produces a 32-byte WRAP header followed by RC4-encrypted data.
        This bypasses impacket's GSS_Wrap_LDAP which has a MechIndepToken
        wrapping mismatch and a confounder bug in the decrypt path.
        """
        key = self._krb_session_key

        # 1-byte padding per RFC 4757
        data += b'\x01'

        # WRAP header prefix (8 bytes): TOK_ID, SGN_ALG, SEAL_ALG, Filler
        header_prefix = struct.pack('<HHHH', 0x0102, 0x0011, 0x0010, 0xFFFF)

        # SND_SEQ: seq number (BE) + direction indicator (initiator = 0x00000000)
        snd_seq_raw = struct.pack('>L', seq_num) + b'\x00\x00\x00\x00'

        # Random 8-byte confounder
        confounder = os.urandom(8)

        # Signing key
        Ksign = HMAC.new(key.contents, b'signaturekey\0', MD5).digest()

        # SGN_CKSUM
        sgn_inner = MD5.new(
            struct.pack('<L', 13) + header_prefix + confounder + data
        ).digest()
        sgn_cksum = HMAC.new(Ksign, sgn_inner, MD5).digest()[:8]

        # Sealing key
        Klocal = bytes(b ^ 0xF0 for b in key.contents)
        Kcrypt = HMAC.new(Klocal, struct.pack('<L', 0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt, struct.pack('>L', seq_num), MD5).digest()

        # Encrypt confounder + data as one continuous RC4 stream
        rc4 = ARC4.new(Kcrypt)
        enc_confounder = rc4.encrypt(confounder)
        enc_data = rc4.encrypt(data)

        # Encrypt SND_SEQ
        Kseq = HMAC.new(key.contents, struct.pack('<L', 0), MD5).digest()
        Kseq = HMAC.new(Kseq, sgn_cksum, MD5).digest()
        enc_snd_seq = ARC4.new(Kseq).encrypt(snd_seq_raw)

        # Complete bare token: header(8) + SND_SEQ(8) + SGN_CKSUM(8) + Confounder(8) + data
        return header_prefix + enc_snd_seq + sgn_cksum + enc_confounder + enc_data

    def _rc4_unwrap(self, payload):
        """Unwrap RFC 4757 RC4-HMAC wrapped data (handles both bare and MechIndepToken).

        The key derivation is self-contained: the decryption key is derived
        from the token's embedded SGN_CKSUM and SND_SEQ, not from external
        sequence numbers or direction parameters.
        """
        key = self._krb_session_key

        # Strip MechIndepToken wrapper if present (Windows may use it for RC4)
        if payload[0:1] == b'\x60':
            from impacket.krb5.gssapi import MechIndepToken
            mit = MechIndepToken.from_bytes(payload)
            payload = mit.data

        # Parse 32-byte WRAP header:
        # header_prefix(8) + SND_SEQ(8) + SGN_CKSUM(8) + Confounder(8)
        enc_snd_seq = payload[8:16]
        sgn_cksum = payload[16:24]
        enc_confounder = payload[24:32]
        enc_data = payload[32:]

        # Derive sequence key and decrypt SND_SEQ
        Kseq = HMAC.new(key.contents, struct.pack('<L', 0), MD5).digest()
        Kseq = HMAC.new(Kseq, sgn_cksum, MD5).digest()
        snd_seq = ARC4.new(Kseq).encrypt(enc_snd_seq)  # RC4 encrypt == decrypt

        # Derive decryption key from sender's sequence number
        Klocal = bytes(b ^ 0xF0 for b in key.contents)
        Kcrypt = HMAC.new(Klocal, struct.pack('<L', 0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt, snd_seq[:4], MD5).digest()

        # Decrypt confounder + data as one continuous RC4 stream
        rc4 = ARC4.new(Kcrypt)
        plaintext = rc4.decrypt(enc_confounder + enc_data)

        # Skip 8-byte confounder, remove 1-byte padding
        return plaintext[8:-1]

    def auth_kerberos(self) -> None:
        """Authenticate to ADWS using Kerberos via impacket.

        Uses the stored TGT to request a TGS for HOST/<fqdn>, builds an
        AP_REQ manually, wraps it in SPNEGO, and negotiates via NNS handshake.
        After authentication, sets up GSS-API wrap/unwrap for channel encryption.
        """
        logging.info('Authenticating to ADWS via Kerberos')

        # Step 1: Get TGS for HOST/<fqdn>
        servername = Principal(
            'HOST/%s' % self._fqdn,
            type=krb5_constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername, self._domain_for_tgs, self._kdc,
            self._tgt['KDC_REP'], self._tgt['cipher'], self._tgt['sessionKey']
        )

        # Step 2: Extract ticket from TGS response
        tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_rep['ticket'])

        # Step 3: Build AP_REQ with mutual authentication required
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(krb5_constants.ApplicationTagNumbers.AP_REQ.value)
        apReq['ap-options'] = krb5_constants.encodeFlags([krb5_constants.APOptions.mutual_required.value])
        seq_set(apReq, 'ticket', ticket.to_asn1)

        # Step 4: Build Authenticator
        username = Principal(
            self._username,
            type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self._domain_for_tgs
        seq_set(authenticator, 'cname', username.components_to_asn1)
        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        # Step 5: Add GSS checksum with required security flags
        # NNS requires mutual auth, confidentiality, integrity, replay & sequence detection
        GSS_C_CONF_FLAG = 16
        GSS_C_INTEG_FLAG = 32
        gss_flags = (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
                     GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG)

        authenticator['cksum'] = noValue
        authenticator['cksum']['cksumtype'] = 0x8003
        chkField = CheckSumField()
        chkField['Lgth'] = 16
        chkField['Flags'] = gss_flags
        authenticator['cksum']['checksum'] = chkField.getData()

        # Step 6: Encrypt authenticator with TGS session key (key usage 11)
        encodedAuthenticator = encoder.encode(authenticator)
        encryptedEncodedAuthenticator = cipher.encrypt(
            sessionkey, 11, encodedAuthenticator, None
        )

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        # Step 7: Wrap AP_REQ in SPNEGO NegTokenInit
        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
        blob['MechToken'] = encoder.encode(apReq)

        # Step 8: Send via NNS handshake
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=blob.getData(),
        ).send(self._sock)

        # Step 9: Receive server response (mutual auth handshake)
        NNS_msg_resp = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Check for errors
        if NNS_msg_resp["message_id"] == MessageID.ERROR:
            err_code = int.from_bytes(NNS_msg_resp["payload"], "big")
            if err_code in ERROR_MESSAGES:
                err_type, err_msg = ERROR_MESSAGES[err_code]
                raise SystemExit(f"[-] Kerberos Auth Failed: {err_type} {err_msg}")
            raise SystemExit(f"[-] Kerberos Auth Failed with error code: 0x{err_code:08x}")

        # Handle mutual auth: server sends DONE or IN_PROGRESS with AP_REP
        server_payload = NNS_msg_resp["payload"]
        if NNS_msg_resp["message_id"] == MessageID.IN_PROGRESS:
            # Server needs another round - send empty DONE to complete
            logging.debug('Processing mutual auth response from server')
            NNS_handshake(
                message_id=MessageID.DONE,
                major_version=1,
                minor_version=0,
                payload=b'',
            ).send(self._sock)

            # Receive final DONE
            NNS_msg_final = NNS_handshake(
                message_id=int.from_bytes(self._sock.recv(1), "big"),
                major_version=int.from_bytes(self._sock.recv(1), "big"),
                minor_version=int.from_bytes(self._sock.recv(1), "big"),
                payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
            )
            if NNS_msg_final["message_id"] == MessageID.ERROR:
                err_code = int.from_bytes(NNS_msg_final["payload"], "big")
                raise SystemExit(f"[-] Kerberos Auth Failed at final step with error code: 0x{err_code:08x}")

        elif NNS_msg_resp["message_id"] != MessageID.DONE:
            raise SystemExit(f"[-] Kerberos Auth: Unexpected message ID: 0x{NNS_msg_resp['message_id']:02x}")

        logging.debug('Kerberos authentication successful')

        # Step 10: Process AP_REP to extract subkey (if present)
        # The server's response contains a SPNEGO NegTokenResp wrapping an AP_REP.
        # The AP_REP may contain a subkey that MUST be used for subsequent encryption.
        enc_key = sessionkey
        if server_payload and len(server_payload) > 0:
            try:
                spnego_resp = SPNEGO_NegTokenResp(server_payload)
                ap_rep_data = spnego_resp['ResponseToken']
                if ap_rep_data and len(ap_rep_data) > 0:
                    raw_token = bytes(ap_rep_data)
                    # The ResponseToken may be wrapped in a GSS-API InitialContextToken
                    # (APPLICATION 0 = 0x60) containing an OID + optional token-id + AP_REP.
                    # We need to find the actual AP_REP (APPLICATION 15 = 0x6F) inside.
                    if raw_token[0] != 0x6F:
                        ap_rep_idx = raw_token.find(b'\x6f')
                        if ap_rep_idx >= 0:
                            raw_token = raw_token[ap_rep_idx:]
                        else:
                            raise ValueError('No AP_REP (0x6F) found in ResponseToken')
                    ap_rep = decoder.decode(raw_token, asn1Spec=AP_REP())[0]
                    enc_part = ap_rep['enc-part']
                    # Decrypt AP_REP enc-part with TGS session key (key usage 12)
                    dec_part = cipher.decrypt(sessionkey, 12, bytes(enc_part['cipher']))
                    enc_ap_rep = decoder.decode(dec_part, asn1Spec=EncAPRepPart())[0]

                    # Extract subkey if server provided one
                    if enc_ap_rep['subkey'] and enc_ap_rep['subkey'].hasValue():
                        subkey_type = int(enc_ap_rep['subkey']['keytype'])
                        subkey_value = bytes(enc_ap_rep['subkey']['keyvalue'])
                        enc_key = KerberosKey(subkey_type, subkey_value)
                        logging.debug('Using subkey from AP_REP (etype %d, %d bytes)',
                                     subkey_type, len(subkey_value))
                    else:
                        logging.debug('No subkey in AP_REP, using TGS session key')
            except Exception as e:
                logging.debug('Could not process AP_REP for subkey: %s', e)

        # Step 11: Set up GSS-API wrap/unwrap for channel encryption
        # GSSAPI() factory only checks .enctype on the passed object to select the
        # right wrapper (RC4/AES128/AES256). KerberosKey has .enctype, so passing
        # enc_key directly picks the correct GSSAPI class even when the subkey
        # etype differs from the TGS session key etype.
        self._gss = krb5_gssapi.GSSAPI(enc_key)
        self._krb_session_key = enc_key
        self._sequence = 0          # client send sequence counter
        self._recv_sequence = 0     # server recv sequence counter

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",
            domain="",
            signingRequired=True,
            use_ntlmv2=True,
        )

        # Generate the NegTokenInit
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Begin authentication (NTLMSSP_NEGOTIATE)
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Extract the NegTokenResp
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP (ResponseToken)
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # Create the NTLMSSP challenge response
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("Using extended NTLM security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("Using basic NTLM auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Send the NTLMSSP_AUTH (challenge response)
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Check for success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # check for errors
        if NNS_msg_done["message_id"] == 0x15:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")
