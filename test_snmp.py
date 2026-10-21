#!/usr/bin/env python3
# =============================================================================
# test_snmp.py  —  Self-contained test suite for the SNMP codec
#
# Tests the BER encoder/decoder and PDU builder/parser WITHOUT a network.
# Run this first to verify everything works before starting agent/manager.
#
# Usage:  python3 test_snmp.py
# =============================================================================

import sys
import traceback
from datetime import datetime

# We test snmp_core directly
from snmp_core import (
    encode_integer, encode_oid, encode_octet_string, encode_null,
    encode_timeticks, encode_counter32, encode_varbind, encode_varbind_list,
    encode_sequence, decode_integer, decode_oid, decode_octet_string,
    decode_value, parse_message, DecodeError,
    build_get_request, build_get_next_request, build_get_bulk_request,
    build_response, build_trap_v2c, build_trap_v1, build_set_request,
    oid_to_tuple, compare_oids, oid_is_prefix, format_message_detail,
    Tag, ErrorStatus,
)
from config import (
    OID_TEMPERATURE, OID_HUMIDITY, OID_AC_STATUS, OID_FAN_STATUS,
    OID_ALERT_STATUS, OID_TRAP_TEMP_ALERT, ENTERPRISE_OID,
    ALL_SCALAR_OIDS, COMMUNITY_READ,
)

PASS = '\033[92m✓ PASS\033[0m'
FAIL = '\033[91m✗ FAIL\033[0m'

results = []


def test(name, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append(True)
    except Exception as e:
        print(f"  {FAIL}  {name}")
        print(f"         {e}")
        traceback.print_exc()
        results.append(False)


# =============================================================================
def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")
# =============================================================================


section("BER INTEGER ENCODING / DECODING")

def t_int_zero():
    raw = encode_integer(0)
    assert raw == bytes([0x02, 0x01, 0x00]), f"Got {raw.hex()}"
    assert decode_integer(raw[2:]) == 0

def t_int_positive_small():
    raw = encode_integer(42)
    val = decode_integer(raw[2:])
    assert val == 42, f"Got {val}"

def t_int_positive_large():
    raw = encode_integer(9999)
    val = decode_integer(raw[2:])
    assert val == 9999, f"Got {val}"

def t_int_negative():
    raw = encode_integer(-1)
    val = decode_integer(raw[2:])
    assert val == -1, f"Got {val}"

def t_int_negative_large():
    for n in [-128, -256, -1000, -32768]:
        raw = encode_integer(n)
        val = decode_integer(raw[2:])
        assert val == n, f"Expected {n}, got {val}"

def t_int_roundtrip_many():
    for n in [0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 0x7FFFFFFF,
              -1, -127, -128, -129, -256, -32768, -0x80000000]:
        raw = encode_integer(n)
        val = decode_integer(raw[2:])
        assert val == n, f"RT fail: {n} → {raw.hex()} → {val}"

test("zero",                  t_int_zero)
test("positive small",        t_int_positive_small)
test("positive large (9999)", t_int_positive_large)
test("negative (-1)",         t_int_negative)
test("negative large",        t_int_negative_large)
test("round-trip many values",t_int_roundtrip_many)


section("BER OID ENCODING / DECODING")

def t_oid_standard():
    oid = '1.3.6.1.4.1.9999.1.0'
    raw = encode_oid(oid)
    assert raw[0] == Tag.OID
    recovered = decode_oid(raw[2:])
    assert recovered == oid, f"Got {recovered}"

def t_oid_sysuptime():
    oid = '1.3.6.1.2.1.1.3.0'
    raw = encode_oid(oid)
    recovered = decode_oid(raw[2:])
    assert recovered == oid, f"Got {recovered}"

def t_oid_all_scalar():
    for oid in ALL_SCALAR_OIDS:
        raw = encode_oid(oid)
        recovered = decode_oid(raw[2:])
        assert recovered == oid, f"OID RT fail: {oid} → {recovered}"

def t_oid_enterprise():
    oid = ENTERPRISE_OID   # '1.3.6.1.4.1.9999'
    raw = encode_oid(oid)
    assert decode_oid(raw[2:]) == oid

test("standard MIB OID",      t_oid_standard)
test("sysUpTime OID",         t_oid_sysuptime)
test("all scalar OIDs",       t_oid_all_scalar)
test("enterprise base OID",   t_oid_enterprise)


section("BER STRING / NULL ENCODING")

def t_octet_str():
    s = 'public'
    raw = encode_octet_string(s)
    assert raw[0] == Tag.OCTET_STRING
    assert decode_octet_string(raw[2:]) == s

def t_null():
    raw = encode_null()
    assert raw == bytes([Tag.NULL, 0x00])

def t_timeticks():
    for v in [0, 1, 100, 65535, 0xFFFFFFFF]:
        raw = encode_timeticks(v)
        assert raw[0] == Tag.TIMETICKS

test("OctetString round-trip", t_octet_str)
test("NULL encoding",          t_null)
test("TimeTicks values",       t_timeticks)


section("PDU BUILDER — GetRequest")

def t_get_request_build_parse():
    oids = [OID_TEMPERATURE, OID_HUMIDITY, OID_AC_STATUS]
    raw, req_id = build_get_request(COMMUNITY_READ, oids, version=1)

    # Must start with SEQUENCE tag
    assert raw[0] == Tag.SEQUENCE, f"Bad outer tag: 0x{raw[0]:02X}"

    msg = parse_message(raw)
    assert msg['pdu_type']   == Tag.GET_REQUEST, f"Bad PDU type: {msg['pdu_type']}"
    assert msg['community']  == COMMUNITY_READ
    assert msg['request_id'] == req_id
    assert msg['error_status'] == 0
    assert msg['error_index']  == 0
    assert len(msg['varbinds']) == 3

    for i, (oid, val, tname) in enumerate(msg['varbinds']):
        assert oid   == oids[i], f"OID mismatch: {oid}"
        assert tname == 'Null'

def t_get_all_scalars():
    raw, req_id = build_get_request(COMMUNITY_READ, ALL_SCALAR_OIDS)
    msg = parse_message(raw)
    assert len(msg['varbinds']) == 5
    for i, (oid, _, _) in enumerate(msg['varbinds']):
        assert oid == ALL_SCALAR_OIDS[i]

test("build + parse GetRequest (3 OIDs)", t_get_request_build_parse)
test("GetRequest with all 5 scalar OIDs", t_get_all_scalars)


section("PDU BUILDER — GetNextRequest")

def t_getnext_build_parse():
    oid = OID_TEMPERATURE
    raw, req_id = build_get_next_request(COMMUNITY_READ, [oid])
    msg = parse_message(raw)
    assert msg['pdu_type']  == Tag.GET_NEXT_REQUEST
    assert msg['varbinds'][0][0] == oid

test("build + parse GetNextRequest", t_getnext_build_parse)


section("PDU BUILDER — GetBulkRequest")

def t_getbulk_build_parse():
    oid = ENTERPRISE_OID
    raw, req_id = build_get_bulk_request(
        COMMUNITY_READ, [oid],
        non_repeaters=0, max_repetitions=5
    )
    msg = parse_message(raw)
    assert msg['pdu_type']     == Tag.GET_BULK_REQUEST
    assert msg['error_status'] == 0   # non_repeaters
    assert msg['error_index']  == 5   # max_repetitions

test("build + parse GetBulkRequest", t_getbulk_build_parse)


section("PDU BUILDER — GetResponse")

def t_response_build_parse():
    from snmp_core import encode_integer as ei
    varbinds = [
        (OID_TEMPERATURE, ei(28)),
        (OID_HUMIDITY,    ei(62)),
        (OID_AC_STATUS,   ei(1)),
        (OID_FAN_STATUS,  ei(1)),
        (OID_ALERT_STATUS,ei(0)),
    ]
    raw = build_response(COMMUNITY_READ, 42,
                         0, 0,
                         varbinds, version=1)
    msg = parse_message(raw)
    assert msg['pdu_type']    == Tag.GET_RESPONSE
    assert msg['request_id']  == 42
    assert msg['error_status']== 0
    assert len(msg['varbinds']) == 5
    assert msg['varbinds'][0][1] == 28   # temperature value
    assert msg['varbinds'][1][1] == 62   # humidity value
    assert msg['varbinds'][2][1] == 1    # acStatus value

def t_response_with_error():
    from snmp_core import encode_null as en
    varbinds = [(OID_TEMPERATURE, en())]
    raw = build_response(COMMUNITY_READ, 7,
                         ErrorStatus.NO_SUCH_NAME, 1,
                         varbinds)
    msg = parse_message(raw)
    assert msg['error_status'] == ErrorStatus.NO_SUCH_NAME
    assert msg['error_index']  == 1

test("build + parse GetResponse (5 values)", t_response_build_parse)
test("GetResponse with error status",         t_response_with_error)


section("PDU BUILDER — Trap v2c")

def t_trap_v2c_build_parse():
    from snmp_core import encode_integer as ei
    varbinds = [
        (OID_TEMPERATURE,  ei(37)),
        (OID_HUMIDITY,     ei(60)),
        (OID_ALERT_STATUS, ei(1)),
    ]
    raw = build_trap_v2c(
        community=COMMUNITY_READ,
        trap_oid=OID_TRAP_TEMP_ALERT,
        varbinds=varbinds,
        uptime_hundredths=12345,
    )
    msg = parse_message(raw)
    assert msg['pdu_type'] == Tag.TRAP_V2C, f"Wrong PDU type: {msg['pdu_type']}"
    # First two varbinds MUST be sysUpTime.0 and snmpTrapOID.0
    assert msg['varbinds'][0][0] == '1.3.6.1.2.1.1.3.0'   # sysUpTime
    assert msg['varbinds'][0][2] == 'TimeTicks'
    assert msg['varbinds'][1][0] == '1.3.6.1.6.3.1.1.4.1.0'  # snmpTrapOID
    # snmpTrapOID value should be the trap OID
    assert OID_TRAP_TEMP_ALERT in str(msg['varbinds'][1][1])
    # Payload varbinds follow
    assert msg['varbinds'][2][0] == OID_TEMPERATURE
    assert msg['varbinds'][2][1] == 37

def t_trap_v1_build_parse():
    from snmp_core import encode_integer as ei
    varbinds = [(OID_ALERT_STATUS, ei(1))]
    raw = build_trap_v1(
        community=COMMUNITY_READ,
        enterprise_oid=ENTERPRISE_OID,
        agent_addr='127.0.0.1',
        generic_trap=6,       # enterprise-specific
        specific_trap=1,
        varbinds=varbinds,
        uptime_hundredths=9900,
    )
    msg = parse_message(raw)
    assert msg['pdu_type'] == Tag.TRAP_V1
    assert msg['enterprise'] == ENTERPRISE_OID
    assert msg['agent_addr'] == '127.0.0.1'
    assert msg['generic_trap'] == 6
    assert msg['specific_trap'] == 1

test("build + parse Trap v2c (with mandatory var-binds)", t_trap_v2c_build_parse)
test("build + parse Trap v1",                             t_trap_v1_build_parse)


section("PDU BUILDER — SetRequest")

def t_set_request():
    from snmp_core import encode_integer as ei
    varbinds = [(OID_TEMPERATURE, ei(99))]
    raw, req_id = build_set_request(COMMUNITY_READ, varbinds)
    msg = parse_message(raw)
    assert msg['pdu_type'] == Tag.SET_REQUEST
    assert msg['varbinds'][0][1] == 99

test("build + parse SetRequest", t_set_request)


section("OID COMPARISON & TREE OPERATIONS")

def t_oid_compare():
    assert compare_oids(OID_TEMPERATURE, OID_HUMIDITY)   < 0   # .1 < .2
    assert compare_oids(OID_HUMIDITY,    OID_TEMPERATURE) > 0
    assert compare_oids(OID_TEMPERATURE, OID_TEMPERATURE) == 0

def t_oid_prefix():
    assert oid_is_prefix(ENTERPRISE_OID, OID_TEMPERATURE)  is True
    assert oid_is_prefix(ENTERPRISE_OID, OID_HUMIDITY)     is True
    assert oid_is_prefix('1.3.6.1.2',   OID_TEMPERATURE)  is False

def t_oid_order():
    # All scalar OIDs must be in strictly ascending order
    oids = ALL_SCALAR_OIDS
    for i in range(len(oids) - 1):
        assert compare_oids(oids[i], oids[i+1]) < 0, \
            f"Order violation: {oids[i]} ≥ {oids[i+1]}"

test("OID comparison (<, >, ==)",        t_oid_compare)
test("OID prefix check",                 t_oid_prefix)
test("All scalar OIDs in ascending order", t_oid_order)


section("MESSAGE FORMATTER")

def t_format_detail():
    raw, req_id = build_get_request(COMMUNITY_READ, [OID_TEMPERATURE])
    msg = parse_message(raw)
    text = format_message_detail(msg, direction='out')
    assert 'GetRequest' in text
    assert COMMUNITY_READ in text
    assert OID_TEMPERATURE in text
    assert str(req_id) in text

test("format_message_detail output", t_format_detail)


# =============================================================================
section("SIMULATED FULL REQUEST/RESPONSE CYCLE")
# =============================================================================

def t_full_cycle():
    """
    Simulate a complete SNMP request/response exchange in-memory,
    exactly as the agent would process it.
    """
    from snmp_core import (
        encode_integer as ei, encode_null,
        build_get_request, build_response, parse_message,
    )

    # Manager builds a GetRequest for temperature + humidity
    req_raw, req_id = build_get_request(
        COMMUNITY_READ,
        [OID_TEMPERATURE, OID_HUMIDITY],
        version=1
    )

    # Agent parses the request
    req_msg = parse_message(req_raw)
    assert req_msg['pdu_type'] == Tag.GET_REQUEST
    assert req_msg['request_id'] == req_id

    # Agent looks up values (simulated store)
    fake_store = {OID_TEMPERATURE: 29, OID_HUMIDITY: 67}
    varbinds_out = []
    for oid, _v, _t in req_msg['varbinds']:
        val = fake_store.get(oid)
        varbinds_out.append((oid, ei(val) if val is not None else encode_null()))

    # Agent builds response
    resp_raw = build_response(
        req_msg['community'],
        req_msg['request_id'],
        ErrorStatus.NO_ERROR, 0,
        varbinds_out,
        version=1,
    )

    # Manager parses response
    resp_msg = parse_message(resp_raw)
    assert resp_msg['pdu_type']    == Tag.GET_RESPONSE
    assert resp_msg['request_id']  == req_id
    assert resp_msg['error_status']== 0

    # Check values
    assert resp_msg['varbinds'][0] == (OID_TEMPERATURE, 29, 'Integer32')
    assert resp_msg['varbinds'][1] == (OID_HUMIDITY,    67, 'Integer32')

test("full request → parse → response → parse cycle", t_full_cycle)


# =============================================================================
# RESULTS
# =============================================================================

total   = len(results)
passed  = sum(results)
failed  = total - passed

print(f"\n{'='*60}")
print(f"  Results:  {passed}/{total} passed", end='')
if failed:
    print(f"   ← \033[91m{failed} FAILED\033[0m")
else:
    print(f"  \033[92m✓ ALL TESTS PASSED\033[0m")
print(f"{'='*60}\n")

if failed:
    sys.exit(1)
