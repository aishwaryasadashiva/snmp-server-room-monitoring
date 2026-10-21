# =============================================================================
# snmp_core.py  —  SNMP BER Codec & PDU Builder/Parser
#
# Implements SNMP v1 and v2c from scratch using raw ASN.1/BER encoding.
# No third-party SNMP libraries required — only Python standard library.
#
# SNMP uses a subset of ASN.1 with Basic Encoding Rules (BER).
# Every value is encoded as:    TAG | LENGTH | VALUE  (TLV triplet)
#
# Supported PDU types:
#   GetRequest      (0xA0) — Manager → Agent: fetch one or more OIDs
#   GetNextRequest  (0xA1) — Manager → Agent: fetch next OID in MIB tree
#   GetResponse     (0xA2) — Agent → Manager: return values or error
#   SetRequest      (0xA3) — Manager → Agent: write a value (agent may reject)
#   Trap v1         (0xA4) — Agent → Manager: SNMPv1 unsolicited notification
#   GetBulkRequest  (0xA5) — Manager → Agent: fetch many OIDs efficiently (v2c)
#   InformRequest   (0xA6) — Agent → Manager: acknowledged notification (v2c)
#   Trap v2c        (0xA7) — Agent → Manager: SNMPv2c unsolicited notification
# =============================================================================

import struct
import time
from enum import IntEnum


# ── ASN.1 / BER Tag Constants ──────────────────────────────────────────────
class Tag(IntEnum):
    INTEGER         = 0x02
    OCTET_STRING    = 0x04
    NULL            = 0x05
    OID             = 0x06
    SEQUENCE        = 0x30
    # SNMP application tags
    IP_ADDRESS      = 0x40   # 4-byte IPv4 address
    COUNTER32       = 0x41   # 32-bit monotonic counter
    GAUGE32         = 0x42   # 32-bit gauge
    TIMETICKS       = 0x43   # hundredths of a second since agent start
    OPAQUE          = 0x44
    COUNTER64       = 0x46   # 64-bit counter (v2c only)
    NO_SUCH_OBJECT  = 0x80   # v2c exception
    NO_SUCH_INSTANCE= 0x81   # v2c exception
    END_OF_MIB_VIEW = 0x82   # v2c exception
    # PDU types (Context-specific, constructed)
    GET_REQUEST         = 0xA0
    GET_NEXT_REQUEST    = 0xA1
    GET_RESPONSE        = 0xA2
    SET_REQUEST         = 0xA3
    TRAP_V1             = 0xA4
    GET_BULK_REQUEST    = 0xA5
    INFORM_REQUEST      = 0xA6
    TRAP_V2C            = 0xA7


# ── SNMP Error Status Codes ────────────────────────────────────────────────
class ErrorStatus(IntEnum):
    NO_ERROR            = 0
    TOO_BIG             = 1
    NO_SUCH_NAME        = 2   # v1 only
    BAD_VALUE           = 3
    READ_ONLY           = 4
    GEN_ERR             = 5
    NO_ACCESS           = 6
    WRONG_TYPE          = 7
    WRONG_LENGTH        = 8
    WRONG_ENCODING      = 9
    WRONG_VALUE         = 10
    NO_CREATION         = 11
    INCONSISTENT_VALUE  = 12
    RESOURCE_UNAVAILABLE= 13
    COMMIT_FAILED       = 14
    UNDO_FAILED         = 15
    AUTHORIZATION_ERROR = 16
    NOT_WRITABLE        = 17
    INCONSISTENT_NAME   = 18

ERROR_STATUS_NAMES = {e.value: e.name for e in ErrorStatus}

PDU_TYPE_NAMES = {
    Tag.GET_REQUEST:      'GetRequest',
    Tag.GET_NEXT_REQUEST: 'GetNextRequest',
    Tag.GET_RESPONSE:     'GetResponse',
    Tag.SET_REQUEST:      'SetRequest',
    Tag.TRAP_V1:          'Trap-v1',
    Tag.GET_BULK_REQUEST: 'GetBulkRequest',
    Tag.INFORM_REQUEST:   'InformRequest',
    Tag.TRAP_V2C:         'Trap-v2c',
}

SNMP_VERSION_NAMES = {0: 'SNMPv1', 1: 'SNMPv2c', 3: 'SNMPv3'}


# =============================================================================
# BER ENCODER
# =============================================================================

def _encode_length(n: int) -> bytes:
    """Encode an ASN.1 BER length field."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    else:
        raise OverflowError(f"Length {n} too large for BER encoding")


def _tlv(tag: int, value: bytes) -> bytes:
    """Wrap value bytes with a TLV header."""
    return bytes([tag]) + _encode_length(len(value)) + value


def encode_integer(value: int, tag: int = Tag.INTEGER) -> bytes:
    """
    Encode a signed integer in BER.
    Handles 0, positives, and negatives (two's complement).
    """
    if value == 0:
        return _tlv(tag, b'\x00')
    if value > 0:
        # Build big-endian bytes
        result = []
        n = value
        while n > 0:
            result.insert(0, n & 0xFF)
            n >>= 8
        # Ensure no accidental sign bit
        if result[0] & 0x80:
            result.insert(0, 0x00)
        return _tlv(tag, bytes(result))
    else:
        # Negative: two's complement
        result = []
        n = -value
        while n > 0:
            result.insert(0, n & 0xFF)
            n >>= 8
        # Flip bits and add 1
        flipped = [(~b) & 0xFF for b in result]
        carry = 1
        for i in range(len(flipped) - 1, -1, -1):
            s = flipped[i] + carry
            flipped[i] = s & 0xFF
            carry = s >> 8
        if carry:
            flipped.insert(0, 0x01)
        # Must have MSB set for negative
        if not (flipped[0] & 0x80):
            flipped.insert(0, 0xFF)
        return _tlv(tag, bytes(flipped))


def encode_timeticks(value: int) -> bytes:
    """Encode TimeTicks (hundredths of a second, unsigned 32-bit)."""
    return encode_integer(value & 0xFFFFFFFF, Tag.TIMETICKS)


def encode_counter32(value: int) -> bytes:
    return encode_integer(value & 0xFFFFFFFF, Tag.COUNTER32)


def encode_gauge32(value: int) -> bytes:
    return encode_integer(value & 0xFFFFFFFF, Tag.GAUGE32)


def encode_octet_string(s, tag: int = Tag.OCTET_STRING) -> bytes:
    """Encode a string or bytes as an OCTET STRING."""
    if isinstance(s, str):
        s = s.encode('utf-8')
    return _tlv(tag, bytes(s))


def encode_null() -> bytes:
    """Encode a NULL value (used as placeholder in request var-binds)."""
    return bytes([Tag.NULL, 0x00])


def encode_oid(oid_str: str) -> bytes:
    """
    Encode a dotted-decimal OID string to BER.
    E.g. '1.3.6.1.4.1.9999.1.0' → bytes

    Algorithm:
      • First two components are merged: byte = 40*c[0] + c[1]
      • Each subsequent component is encoded in base-128 with the MSB
        set on every byte EXCEPT the last (continuation flag).
    """
    parts = [int(x) for x in oid_str.strip().split('.')]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid_str}")

    result = bytearray()
    # First two components
    result.append(40 * parts[0] + parts[1])

    # Remaining components in base-128
    for c in parts[2:]:
        if c == 0:
            result.append(0x00)
        else:
            encoded = []
            while c > 0:
                encoded.insert(0, c & 0x7F)
                c >>= 7
            # Set continuation MSB on all but last byte
            for i in range(len(encoded) - 1):
                encoded[i] |= 0x80
            result.extend(encoded)

    return _tlv(Tag.OID, bytes(result))


def encode_sequence(content: bytes) -> bytes:
    """Wrap bytes in an ASN.1 SEQUENCE."""
    return _tlv(Tag.SEQUENCE, content)


def encode_varbind(oid_str: str, value_bytes: bytes) -> bytes:
    """
    Encode a single VarBind: SEQUENCE { OID, Value }
    """
    return encode_sequence(encode_oid(oid_str) + value_bytes)


def encode_varbind_list(varbinds: list) -> bytes:
    """
    Encode a VarBindList: SEQUENCE OF VarBind
    Each varbind is (oid_str, value_bytes).
    """
    content = b''.join(encode_varbind(oid, val) for oid, val in varbinds)
    return encode_sequence(content)


# =============================================================================
# SNMP MESSAGE BUILDERS
# =============================================================================

_request_id_counter = 1000

def _next_request_id() -> int:
    global _request_id_counter
    _request_id_counter = (_request_id_counter % 0x7FFFFFFF) + 1
    return _request_id_counter


def build_get_request(community: str, oids: list, version: int = 1) -> tuple:
    """
    Build a GetRequest PDU.
    Returns (raw_bytes, request_id).
    VarBind values are NULL (placeholder for GET).
    """
    req_id = _next_request_id()
    varbinds = [(oid, encode_null()) for oid in oids]
    pdu = _build_pdu(Tag.GET_REQUEST, req_id, 0, 0, varbinds)
    msg = _build_message(version, community, pdu)
    return msg, req_id


def build_get_next_request(community: str, oids: list, version: int = 1) -> tuple:
    """
    Build a GetNextRequest PDU.
    Returns (raw_bytes, request_id).
    """
    req_id = _next_request_id()
    varbinds = [(oid, encode_null()) for oid in oids]
    pdu = _build_pdu(Tag.GET_NEXT_REQUEST, req_id, 0, 0, varbinds)
    msg = _build_message(version, community, pdu)
    return msg, req_id


def build_get_bulk_request(community: str, oids: list,
                            non_repeaters: int = 0,
                            max_repetitions: int = 10) -> tuple:
    """
    Build a GetBulkRequest PDU (SNMPv2c only).
    non_repeaters: how many OIDs are non-repeating (returned once)
    max_repetitions: max times to repeat for remaining OIDs

    In GetBulk, the error_status field carries non_repeaters
    and error_index carries max_repetitions.
    """
    req_id = _next_request_id()
    varbinds = [(oid, encode_null()) for oid in oids]
    pdu = _build_pdu(Tag.GET_BULK_REQUEST, req_id,
                     non_repeaters, max_repetitions, varbinds)
    msg = _build_message(1, community, pdu)  # Always v2c
    return msg, req_id


def build_set_request(community: str, varbinds: list, version: int = 1) -> tuple:
    """
    Build a SetRequest PDU.
    varbinds: list of (oid, value_bytes)
    """
    req_id = _next_request_id()
    pdu = _build_pdu(Tag.SET_REQUEST, req_id, 0, 0, varbinds)
    msg = _build_message(version, community, pdu)
    return msg, req_id


def build_response(community: str, request_id: int,
                   error_status: int, error_index: int,
                   varbinds: list, version: int = 1) -> bytes:
    """
    Build a GetResponse PDU.
    varbinds: list of (oid, value_bytes)
    """
    pdu = _build_pdu(Tag.GET_RESPONSE, request_id,
                     error_status, error_index, varbinds)
    return _build_message(version, community, pdu)


def build_trap_v2c(community: str,
                   trap_oid: str,
                   varbinds: list,
                   uptime_hundredths: int = 0) -> bytes:
    """
    Build an SNMPv2c Trap PDU (Trap-PDU type 0xA7).

    SNMPv2c traps MUST include two mandatory var-binds at the start:
      1. sysUpTime.0  (1.3.6.1.2.1.1.3.0)  = TimeTicks
      2. snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) = OID of the trap

    Additional var-binds follow (the 'interesting' data).
    """
    from config import OID_SYS_UPTIME, OID_SNMP_TRAP_OID
    req_id = _next_request_id()

    # Mandatory prefix var-binds
    mandatory = [
        (OID_SYS_UPTIME,    encode_timeticks(uptime_hundredths)),
        (OID_SNMP_TRAP_OID, encode_oid(trap_oid)),
    ]
    all_varbinds = mandatory + list(varbinds)

    pdu = _build_pdu(Tag.TRAP_V2C, req_id, 0, 0, all_varbinds)
    return _build_message(1, community, pdu)   # v2c


def build_trap_v1(community: str,
                  enterprise_oid: str,
                  agent_addr: str,
                  generic_trap: int,
                  specific_trap: int,
                  varbinds: list,
                  uptime_hundredths: int = 0) -> bytes:
    """
    Build an SNMPv1 Trap PDU (Trap-PDU type 0xA4).

    SNMPv1 Trap structure (different from v2c!):
      SEQUENCE {
        INTEGER version (0)
        OctetString community
        Trap-PDU {
          OID enterprise
          IPAddress agent-addr
          INTEGER generic-trap  (0=coldStart, 1=warmStart, 6=enterpriseSpecific)
          INTEGER specific-trap
          TimeTicks time-stamp
          VarBindList
        }
      }
    """
    # Encode agent IP address as 4-byte IPAddress
    octets = [int(x) for x in agent_addr.split('.')]
    ip_bytes = _tlv(Tag.IP_ADDRESS, bytes(octets))

    vbl_content = b''.join(encode_varbind(o, v) for o, v in varbinds)
    vbl = encode_sequence(vbl_content)

    pdu_content = (
        encode_oid(enterprise_oid) +
        ip_bytes +
        encode_integer(generic_trap) +
        encode_integer(specific_trap) +
        encode_timeticks(uptime_hundredths) +
        vbl
    )
    pdu = _tlv(Tag.TRAP_V1, pdu_content)
    return _build_message(0, community, pdu)   # v1


def _build_pdu(pdu_type: int, request_id: int,
               error_status: int, error_index: int,
               varbinds: list) -> bytes:
    """Internal: build a generic PDU (Get/GetNext/Response/Set/Bulk)."""
    vbl = encode_varbind_list(varbinds)
    content = (
        encode_integer(request_id) +
        encode_integer(error_status) +
        encode_integer(error_index) +
        vbl
    )
    return _tlv(pdu_type, content)


def _build_message(version: int, community: str, pdu: bytes) -> bytes:
    """Internal: wrap PDU in an SNMP message envelope."""
    content = (
        encode_integer(version) +
        encode_octet_string(community) +
        pdu
    )
    return encode_sequence(content)


# =============================================================================
# BER DECODER
# =============================================================================

class DecodeError(Exception):
    pass


def _decode_length(data: bytes, pos: int) -> tuple:
    """
    Decode a BER length field starting at pos.
    Returns (length, new_pos).
    """
    if pos >= len(data):
        raise DecodeError("Unexpected end of data while reading length")
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    n_bytes = first & 0x7F
    if n_bytes == 0:
        raise DecodeError("Indefinite length form not supported")
    if pos + 1 + n_bytes > len(data):
        raise DecodeError("Truncated length field")
    length = 0
    for i in range(n_bytes):
        length = (length << 8) | data[pos + 1 + i]
    return length, pos + 1 + n_bytes


def _decode_tlv(data: bytes, pos: int) -> tuple:
    """
    Decode one TLV at position pos.
    Returns (tag, value_bytes, next_pos).
    """
    if pos >= len(data):
        raise DecodeError(f"No data at position {pos}")
    tag = data[pos]
    length, pos = _decode_length(data, pos + 1)
    if pos + length > len(data):
        raise DecodeError(
            f"TLV value truncated: need {length} bytes at pos {pos}, "
            f"have {len(data) - pos}"
        )
    return tag, data[pos:pos + length], pos + length


def decode_integer(data: bytes) -> int:
    """Decode a signed BER integer from raw value bytes."""
    if not data:
        return 0
    # Check sign bit
    result = 0
    for b in data:
        result = (result << 8) | b
    # Two's complement for negative numbers
    if data[0] & 0x80:
        result -= (1 << (8 * len(data)))
    return result


def decode_unsigned(data: bytes) -> int:
    """Decode an unsigned integer (for TimeTicks, Counter32, Gauge32)."""
    result = 0
    for b in data:
        result = (result << 8) | b
    return result


def decode_oid(data: bytes) -> str:
    """
    Decode a BER-encoded OID from raw value bytes.
    Returns dotted-decimal string like '1.3.6.1.4.1.9999.1.0'.
    """
    if not data:
        return ''
    components = [data[0] // 40, data[0] % 40]
    i = 1
    while i < len(data):
        val = 0
        while data[i] & 0x80:  # continuation bit
            val = (val << 7) | (data[i] & 0x7F)
            i += 1
            if i >= len(data):
                raise DecodeError("OID component truncated")
        val = (val << 7) | data[i]
        components.append(val)
        i += 1
    return '.'.join(str(c) for c in components)


def decode_octet_string(data: bytes) -> str:
    """Attempt UTF-8 decode, fall back to hex representation."""
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.hex()


def decode_value(tag: int, data: bytes):
    """Decode a value based on its tag. Returns (python_value, type_name)."""
    if tag == Tag.INTEGER:
        return decode_integer(data), 'Integer32'
    elif tag == Tag.OCTET_STRING:
        return decode_octet_string(data), 'OctetString'
    elif tag == Tag.NULL:
        return None, 'Null'
    elif tag == Tag.OID:
        return decode_oid(data), 'OID'
    elif tag == Tag.TIMETICKS:
        return decode_unsigned(data), 'TimeTicks'
    elif tag == Tag.COUNTER32:
        return decode_unsigned(data), 'Counter32'
    elif tag == Tag.GAUGE32:
        return decode_unsigned(data), 'Gauge32'
    elif tag == Tag.IP_ADDRESS:
        return '.'.join(str(b) for b in data), 'IpAddress'
    elif tag == Tag.COUNTER64:
        return decode_unsigned(data), 'Counter64'
    elif tag == Tag.NO_SUCH_OBJECT:
        return 'noSuchObject', 'Exception'
    elif tag == Tag.NO_SUCH_INSTANCE:
        return 'noSuchInstance', 'Exception'
    elif tag == Tag.END_OF_MIB_VIEW:
        return 'endOfMibView', 'Exception'
    else:
        return data.hex(), f'Unknown(0x{tag:02X})'


# =============================================================================
# SNMP MESSAGE PARSER
# =============================================================================

def parse_message(raw: bytes) -> dict:
    """
    Parse a raw SNMP message (bytes received from UDP socket).

    Returns a dict with:
      version       int         SNMP version (0=v1, 1=v2c)
      community     str         Community string
      pdu_type      int         PDU type tag (see Tag enum)
      pdu_type_name str         Human-readable PDU type
      request_id    int         Request ID
      error_status  int         Error status (or non_repeaters for BULK)
      error_index   int         Error index  (or max_repetitions for BULK)
      varbinds      list        [(oid, value, type_name), ...]
      raw           bytes       Original raw bytes
    """
    try:
        pos = 0
        # Outer SEQUENCE
        tag, msg_data, _ = _decode_tlv(raw, pos)
        if tag != Tag.SEQUENCE:
            raise DecodeError(f"Expected SEQUENCE (0x30), got 0x{tag:02X}")

        pos = 0
        # Version
        tag, val, pos = _decode_tlv(msg_data, pos)
        version = decode_integer(val)

        # Community
        tag, val, pos = _decode_tlv(msg_data, pos)
        community = decode_octet_string(val)

        # PDU
        pdu_tag, pdu_data, _ = _decode_tlv(msg_data, pos)
        pdu_type = pdu_tag
        pdu_type_name = PDU_TYPE_NAMES.get(pdu_tag, f'Unknown(0x{pdu_tag:02X})')

        # Trap v1 has different structure
        if pdu_tag == Tag.TRAP_V1:
            return _parse_trap_v1(version, community, pdu_data, raw)

        # Standard PDU fields
        pos = 0
        tag, val, pos = _decode_tlv(pdu_data, pos)
        request_id = decode_integer(val)

        tag, val, pos = _decode_tlv(pdu_data, pos)
        error_status = decode_integer(val)

        tag, val, pos = _decode_tlv(pdu_data, pos)
        error_index = decode_integer(val)

        # VarBindList
        tag, vbl_data, pos = _decode_tlv(pdu_data, pos)
        varbinds = _parse_varbind_list(vbl_data)

        return {
            'version':        version,
            'version_name':   SNMP_VERSION_NAMES.get(version, f'v{version}'),
            'community':      community,
            'pdu_type':       pdu_type,
            'pdu_type_name':  pdu_type_name,
            'request_id':     request_id,
            'error_status':   error_status,
            'error_status_name': ERROR_STATUS_NAMES.get(error_status, str(error_status)),
            'error_index':    error_index,
            'varbinds':       varbinds,
            'raw':            raw,
        }

    except Exception as e:
        raise DecodeError(f"Failed to parse SNMP message: {e}") from e


def _parse_trap_v1(version: int, community: str, pdu_data: bytes, raw: bytes) -> dict:
    """Parse an SNMPv1 Trap PDU (different structure from other PDUs)."""
    pos = 0
    tag, val, pos = _decode_tlv(pdu_data, pos)
    enterprise = decode_oid(val)

    tag, val, pos = _decode_tlv(pdu_data, pos)
    agent_addr = '.'.join(str(b) for b in val)

    tag, val, pos = _decode_tlv(pdu_data, pos)
    generic_trap = decode_integer(val)

    tag, val, pos = _decode_tlv(pdu_data, pos)
    specific_trap = decode_integer(val)

    tag, val, pos = _decode_tlv(pdu_data, pos)
    time_stamp = decode_unsigned(val)

    tag, vbl_data, pos = _decode_tlv(pdu_data, pos)
    varbinds = _parse_varbind_list(vbl_data)

    return {
        'version':        version,
        'version_name':   'SNMPv1',
        'community':      community,
        'pdu_type':       Tag.TRAP_V1,
        'pdu_type_name':  'Trap-v1',
        'request_id':     0,
        'error_status':   0,
        'error_status_name': 'noError',
        'error_index':    0,
        'enterprise':     enterprise,
        'agent_addr':     agent_addr,
        'generic_trap':   generic_trap,
        'specific_trap':  specific_trap,
        'time_stamp':     time_stamp,
        'varbinds':       varbinds,
        'raw':            raw,
    }


def _parse_varbind_list(vbl_data: bytes) -> list:
    """
    Parse a VarBindList.
    Returns list of (oid_str, value, type_name) tuples.
    """
    result = []
    pos = 0
    while pos < len(vbl_data):
        tag, vb_data, pos = _decode_tlv(vbl_data, pos)
        if tag != Tag.SEQUENCE:
            continue  # Skip unexpected data

        vpos = 0
        # OID
        otag, oval, vpos = _decode_tlv(vb_data, vpos)
        oid = decode_oid(oval)

        # Value
        vtag, vval, vpos = _decode_tlv(vb_data, vpos)
        value, type_name = decode_value(vtag, vval)

        result.append((oid, value, type_name))
    return result


# =============================================================================
# UTILITY HELPERS
# =============================================================================

def oid_to_tuple(oid_str: str) -> tuple:
    """Convert '1.3.6.1.4.1.9999.1.0' → (1, 3, 6, 1, 4, 1, 9999, 1, 0)"""
    return tuple(int(x) for x in oid_str.split('.'))


def tuple_to_oid(t: tuple) -> str:
    """Convert (1, 3, 6, 1, 4, 1, 9999, 1, 0) → '1.3.6.1.4.1.9999.1.0'"""
    return '.'.join(str(x) for x in t)


def oid_is_prefix(prefix: str, oid: str) -> bool:
    """Return True if oid starts with prefix."""
    return oid == prefix or oid.startswith(prefix + '.')


def compare_oids(a: str, b: str) -> int:
    """
    Lexicographic OID comparison.
    Returns -1, 0, or 1 (like cmp).
    """
    at = oid_to_tuple(a)
    bt = oid_to_tuple(b)
    if at < bt:
        return -1
    elif at > bt:
        return 1
    return 0


def format_message_detail(msg: dict, direction: str = '?') -> str:
    """
    Format a parsed SNMP message for human-readable display in the log.
    direction: '►' for outgoing, '◄' for incoming
    """
    lines = []
    arrow = '►' if direction == 'out' else '◄'
    pdu_name = msg.get('pdu_type_name', 'Unknown')
    ver = msg.get('version_name', '?')

    lines.append(f"{arrow} {ver} {pdu_name}")
    lines.append(f"   Community : {msg.get('community', '?')}")
    lines.append(f"   Request-ID: {msg.get('request_id', 0)}")

    pdu_type = msg.get('pdu_type', 0)
    if pdu_type == Tag.GET_BULK_REQUEST:
        lines.append(f"   Non-Repeaters   : {msg.get('error_status', 0)}")
        lines.append(f"   Max-Repetitions : {msg.get('error_index', 0)}")
    elif pdu_type not in (Tag.TRAP_V1, Tag.TRAP_V2C):
        es = msg.get('error_status', 0)
        ei = msg.get('error_index', 0)
        esn = msg.get('error_status_name', '')
        lines.append(f"   Error-Status: {es} ({esn})")
        lines.append(f"   Error-Index : {ei}")

    if pdu_type == Tag.TRAP_V1:
        lines.append(f"   Enterprise  : {msg.get('enterprise', '?')}")
        lines.append(f"   Agent-Addr  : {msg.get('agent_addr', '?')}")

    lines.append(f"   VarBinds ({len(msg.get('varbinds', []))}):")
    for oid, val, tname in msg.get('varbinds', []):
        lines.append(f"     {oid}  =  {tname}: {val}")

    return '\n'.join(lines)
