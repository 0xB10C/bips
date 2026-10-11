#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR BSD-2-Clause
"""Generate and verify test vectors for the TCP hole punching BIP draft (v0.2).

Encodings follow the draft: little-endian integers unless noted, BIP 155
address elements with big-endian ports, minimally encoded CompactSize.

Usage:
    python3 gen_vectors.py            # writes vectors.json next to this file
    python3 gen_vectors.py --check    # verifies vectors.json round-trips
"""

import json
import os
import sys
from io import BytesIO

# BIP 155 network IDs
NET_IPV4, NET_IPV6, NET_TORV3, NET_I2P, NET_CJDNS, NET_HOLEPUNCH = 1, 2, 4, 5, 6, 8
ADDR_LEN = {NET_IPV4: 4, NET_IPV6: 16, NET_TORV3: 32, NET_I2P: 32, NET_CJDNS: 16}
ENDPOINT_NETS = (NET_IPV4, NET_IPV6)
COORD_NETS = (NET_IPV4, NET_IPV6, NET_TORV3, NET_I2P)
HOLEPUNCH_LENGTHS = {12, 24, 36, 40, 52}
ROLES = {0, 1}
FEATURE_ID = "https://delvingbitcoin.org/t/2497"
CAPS = {"COORDINATOR": 1 << 0, "ADVERTISED": 1 << 1, "POOL_OK": 1 << 2, "HANDOFF_OK": 1 << 3, "PUNCHPORT": 1 << 4}

NODE_P2P_V2 = 1 << 11
NODE_NETWORK = 1
NODE_WITNESS = 1 << 3


class Malformed(Exception):
    pass


# --- primitives -----------------------------------------------------------

def ser_cs(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def deser_cs(f):
    b = f.read(1)
    if len(b) != 1:
        raise Malformed("truncated CompactSize")
    n = b[0]
    if n < 253:
        return n
    size = {253: 2, 254: 4, 255: 8}[n]
    raw = f.read(size)
    if len(raw) != size:
        raise Malformed("truncated CompactSize")
    v = int.from_bytes(raw, "little")
    minimum = {2: 253, 4: 0x10000, 8: 0x100000000}[size]
    if v < minimum:
        raise Malformed("non-minimal CompactSize")
    return v


def read_exact(f, n, what):
    b = f.read(n)
    if len(b) != n:
        raise Malformed("truncated " + what)
    return b


def ser_u8(v):
    return v.to_bytes(1, "little")


def ser_u32(v):
    return v.to_bytes(4, "little")


def ser_u16be(v):
    return v.to_bytes(2, "big")


# --- endpoint -----------------------------------------------------------------

def ser_endpoint(ep):
    addr = bytes.fromhex(ep["addr"])
    return ser_u8(ep["net"]) + ser_cs(len(addr)) + addr + ser_u16be(ep["port"])


def deser_endpoint(f):
    net = read_exact(f, 1, "net")[0]
    if net not in ENDPOINT_NETS:
        raise Malformed("endpoint net must be IPV4 or IPV6 (R-4.2)")
    alen = deser_cs(f)
    if alen != ADDR_LEN[net]:
        raise Malformed("addr_len does not match net (R-4.2)")
    addr = read_exact(f, alen, "addr")
    port = int.from_bytes(read_exact(f, 2, "port"), "big")
    return {"net": net, "addr": addr.hex(), "port": port}


# --- messages -----------------------------------------------------------------

def ser_rendezvous(m):
    return ser_endpoint(m["target"]) + ser_endpoint(m["requester"])


def deser_rendezvous(f):
    target = deser_endpoint(f)
    requester = deser_endpoint(f)
    if target["net"] != requester["net"]:
        raise Malformed("target and requester family differ (R-4.3)")
    return {"target": target, "requester": requester}


def ser_punch(m):
    return ser_u8(m["role"]) + ser_endpoint(m["peer"])


def deser_punch(f):
    role = read_exact(f, 1, "role")[0]
    if role not in ROLES:
        raise Malformed("unknown role (R-4.2)")
    return {"role": role, "peer": deser_endpoint(f)}


def ser_feature_data(m):
    return ser_u8(m["version"]) + ser_u32(m["caps"])


def deser_feature_data(f):
    version = read_exact(f, 1, "version")[0]
    caps = int.from_bytes(read_exact(f, 4, "caps"), "little")
    return {"version": version, "caps": caps}


MESSAGES = {
    "rendezvous": (ser_rendezvous, deser_rendezvous),
    "punch": (ser_punch, deser_punch),
    "feature_data": (ser_feature_data, deser_feature_data),
}


def decode(kind, payload):
    f = BytesIO(payload)
    out = MESSAGES[kind][1](f)
    if f.read(1):
        raise Malformed("trailing bytes (R-4.1)")
    return out


# --- HOLEPUNCH addrv2 element ---------------------------------------------------

def ser_holepunch_addr(h):
    return (ser_u8(h["coord_net"]) + bytes.fromhex(h["coord_addr"]) + ser_u16be(h["coord_port"])
            + ser_u8(h["target_net"]) + bytes.fromhex(h["target_addr"]))


def deser_holepunch_addr(b):
    if len(b) not in HOLEPUNCH_LENGTHS:
        raise Malformed("invalid HOLEPUNCH length %d (R-6.1)" % len(b))
    f = BytesIO(b)
    coord_net = read_exact(f, 1, "coord_net")[0]
    if coord_net not in COORD_NETS:
        raise Malformed("unknown coord_net (R-6.1)")
    coord_addr = read_exact(f, ADDR_LEN[coord_net], "coord_addr")
    coord_port = int.from_bytes(read_exact(f, 2, "coord_port"), "big")
    if coord_net == NET_I2P and coord_port != 0:
        raise Malformed("I2P coord_port must be 0")
    target_net = read_exact(f, 1, "target_net")[0]
    if target_net not in ENDPOINT_NETS:
        raise Malformed("unknown target_net (R-6.1)")
    target_addr = read_exact(f, ADDR_LEN[target_net], "target_addr")
    if f.read(1):
        raise Malformed("invalid HOLEPUNCH length (R-6.1)")
    return {"coord_net": coord_net, "coord_addr": coord_addr.hex(), "coord_port": coord_port,
            "target_net": target_net, "target_addr": target_addr.hex(),
            "profile": "A" if coord_net in ENDPOINT_NETS else "B"}


def ser_addrv2_element(el):
    addr = bytes.fromhex(el["addr"])
    return ser_u32(el["time"]) + ser_cs(el["services"]) + ser_u8(el["net"]) + ser_cs(len(addr)) + addr + ser_u16be(el["port"])


def deser_addrv2_element(b):
    f = BytesIO(b)
    t = int.from_bytes(read_exact(f, 4, "time"), "little")
    services = deser_cs(f)
    net = read_exact(f, 1, "net")[0]
    alen = deser_cs(f)
    addr = read_exact(f, alen, "addr")
    port = int.from_bytes(read_exact(f, 2, "port"), "big")
    if f.read(1):
        raise Malformed("trailing bytes")
    el = {"time": t, "services": services, "net": net, "addr": addr.hex(), "port": port}
    if net == NET_HOLEPUNCH:
        el["holepunch"] = deser_holepunch_addr(addr)
        if not services & NODE_P2P_V2:
            raise Malformed("services lack NODE_P2P_V2 (R-3.3)")
    return el


# --- fixtures -------------------------------------------------------------------

IPV4_A = {"net": NET_IPV4, "addr": "cb007101", "port": 8335}        # 203.0.113.1
IPV4_B = {"net": NET_IPV4, "addr": "c6336402", "port": 50123}       # 198.51.100.2 (NAT-chosen port)
IPV4_C = {"net": NET_IPV4, "addr": "c0000203", "port": 8333}        # 192.0.2.3 coordinator
IPV6_A = {"net": NET_IPV6, "addr": "20010db8000000000000000000000001", "port": 8335}
IPV6_B = {"net": NET_IPV6, "addr": "20010db8000000000000000000000002", "port": 18335}
IPV6_C = {"net": NET_IPV6, "addr": "20010db8000000000000000000000003", "port": 8333}
ONION = "53cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac"
I2P = "a2894dabaec4a6e5f84ccaa9c0b5bc64bd4e4e7f8a9f5f8c3f7aa6a4dd7e5e56"
CJDNS = "fc000000000000000000000000000001"
TIME = 1760100000
SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2


def build():
    valid, invalid = [], []

    def add_valid(kind, desc, fields):
        payload = MESSAGES[kind][0](fields)
        decoded = decode(kind, payload)
        valid.append({"kind": kind, "description": desc, "hex": payload.hex(), "decoded": decoded})

    def add_invalid(kind, desc, payload_hex, reason):
        try:
            decode(kind, bytes.fromhex(payload_hex))
        except Malformed as e:
            invalid.append({"kind": kind, "description": desc, "hex": payload_hex, "reason": reason, "detected": str(e)})
            return
        raise SystemExit("invalid vector was accepted: " + desc)

    # feature data
    add_valid("feature_data", "version 0, ADVERTISED|PUNCHPORT (advertiser to coordinator)", {"version": 0, "caps": CAPS["ADVERTISED"] | CAPS["PUNCHPORT"]})
    add_valid("feature_data", "version 0, COORDINATOR", {"version": 0, "caps": CAPS["COORDINATOR"]})
    add_valid("feature_data", "version 0, all defined caps", {"version": 0, "caps": 0x1f})
    add_valid("feature_data", "version 0, no caps (plain participant)", {"version": 0, "caps": 0})
    add_valid("feature_data", "version 0, unknown high bit set (must be ignored)", {"version": 0, "caps": 1 << 31})

    # rendezvous
    add_valid("rendezvous", "IPv4 target and requester", {"target": IPV4_A, "requester": IPV4_B})
    add_valid("rendezvous", "IPv6 target and requester", {"target": IPV6_A, "requester": IPV6_B})
    add_valid("rendezvous", "requester port 0 (encodable; rejected by R-5.1 semantics, not parsing)", {"target": IPV4_A, "requester": dict(IPV4_B, port=0)})
    add_invalid("rendezvous", "family mismatch (IPv4 target, IPv6 requester)", (ser_endpoint(IPV4_A) + ser_endpoint(IPV6_B)).hex(), "R-4.3")
    add_invalid("rendezvous", "target with TORV3 net", (ser_u8(NET_TORV3) + ser_cs(32) + bytes.fromhex(ONION) + ser_u16be(8333) + ser_endpoint(IPV4_B)).hex(), "R-4.2 endpoint net")
    add_invalid("rendezvous", "IPv4 target with addr_len 5", (ser_u8(NET_IPV4) + ser_cs(5) + b"\x01" * 5 + ser_u16be(1) + ser_endpoint(IPV4_B)).hex(), "R-4.2 addr_len mismatch")
    add_invalid("rendezvous", "trailing byte", (ser_rendezvous({"target": IPV4_A, "requester": IPV4_B}) + b"\x00").hex(), "R-4.1 trailing bytes")
    add_invalid("rendezvous", "truncated requester port", ser_rendezvous({"target": IPV4_A, "requester": IPV4_B})[:-1].hex(), "R-4.1 missing bytes")
    add_invalid("rendezvous", "non-minimal CompactSize addr_len", (ser_u8(NET_IPV4) + b"\xfd\x04\x00" + bytes.fromhex(IPV4_A["addr"]) + ser_u16be(8335) + ser_endpoint(IPV4_B)).hex(), "non-minimal CompactSize")

    # punch
    add_valid("punch", "initiator with IPv4 peer", {"role": 1, "peer": IPV4_A})
    add_valid("punch", "responder with IPv4 peer", {"role": 0, "peer": IPV4_B})
    add_valid("punch", "initiator with IPv6 peer", {"role": 1, "peer": IPV6_A})
    add_invalid("punch", "role 2", (ser_u8(2) + ser_endpoint(IPV4_A)).hex(), "R-4.2 unknown role")
    add_invalid("punch", "peer with CJDNS net", (ser_u8(1) + ser_u8(NET_CJDNS) + ser_cs(16) + bytes.fromhex(CJDNS) + ser_u16be(8335)).hex(), "R-4.2 endpoint net")
    add_invalid("punch", "trailing byte", (ser_punch({"role": 1, "peer": IPV4_A}) + b"\x00").hex(), "R-4.1 trailing bytes")
    add_invalid("punch", "empty payload", "", "R-4.1 missing bytes")

    # HOLEPUNCH addrv2 elements
    hp_valid, hp_invalid = [], []

    def add_hp_valid(desc, h, port, services=SERVICES):
        addr = ser_holepunch_addr(h)
        el = {"time": TIME, "services": services, "net": NET_HOLEPUNCH, "addr": addr.hex(), "port": port}
        payload = ser_addrv2_element(el)
        decoded = deser_addrv2_element(payload)
        hp_valid.append({"description": desc, "element_hex": payload.hex(), "addr_len": len(addr), "decoded": decoded})

    def add_hp_invalid(desc, element_hex, reason):
        try:
            deser_addrv2_element(bytes.fromhex(element_hex))
        except Malformed as e:
            hp_invalid.append({"description": desc, "element_hex": element_hex, "reason": reason, "detected": str(e)})
            return
        raise SystemExit("invalid HOLEPUNCH vector was accepted: " + desc)

    def hp(coord_net, coord_addr, coord_port, target):
        return {"coord_net": coord_net, "coord_addr": coord_addr, "coord_port": coord_port,
                "target_net": target["net"], "target_addr": target["addr"]}

    add_hp_valid("Profile A, IPv4 coordinator, IPv4 target (12 bytes)", hp(NET_IPV4, IPV4_C["addr"], 8333, IPV4_A), IPV4_A["port"])
    add_hp_valid("Profile A, IPv6 coordinator, IPv4 target (24 bytes)", hp(NET_IPV6, IPV6_C["addr"], 8333, IPV4_A), IPV4_A["port"])
    add_hp_valid("Profile A, IPv4 coordinator, IPv6 target (24 bytes, same length, parsed by net ids)", hp(NET_IPV4, IPV4_C["addr"], 8333, IPV6_A), IPV6_A["port"])
    add_hp_valid("Profile A, IPv6 coordinator, IPv6 target (36 bytes)", hp(NET_IPV6, IPV6_C["addr"], 18333, IPV6_A), IPV6_A["port"])
    add_hp_valid("Profile B, onion coordinator, IPv4 target (40 bytes)", hp(NET_TORV3, ONION, 8333, IPV4_A), IPV4_A["port"])
    add_hp_valid("Profile B, onion coordinator, IPv6 target (52 bytes)", hp(NET_TORV3, ONION, 8333, IPV6_A), IPV6_A["port"])
    add_hp_valid("Profile B, I2P coordinator (port 0), IPv4 target (40 bytes)", hp(NET_I2P, I2P, 0, IPV4_A), IPV4_A["port"])
    add_hp_valid("Profile B, I2P coordinator (port 0), IPv6 target (52 bytes)", hp(NET_I2P, I2P, 0, IPV6_A), IPV6_A["port"])
    add_hp_valid("NAT-chosen target port in the element port field", hp(NET_IPV4, IPV4_C["addr"], 8333, IPV4_B), IPV4_B["port"])

    base = hp(NET_IPV4, IPV4_C["addr"], 8333, IPV4_A)

    def elem(addr_bytes, services=SERVICES, port=8335):
        return ser_addrv2_element({"time": TIME, "services": services, "net": NET_HOLEPUNCH, "addr": addr_bytes.hex(), "port": port}).hex()

    add_hp_invalid("length 13 (trailing byte in addr)", elem(ser_holepunch_addr(base) + b"\x00"), "R-6.1 invalid length")
    add_hp_invalid("length 11 (truncated target)", elem(ser_holepunch_addr(base)[:-1]), "R-6.1 invalid length")
    add_hp_invalid("length 24 with inconsistent net ids (IPv4 coordinator, IPv4 target, padded)", elem(ser_holepunch_addr(base) + b"\x00" * 12), "R-6.1 parsed length mismatch")
    add_hp_invalid("coord_net CJDNS", elem(ser_holepunch_addr(dict(base, coord_net=NET_CJDNS, coord_addr=CJDNS))), "R-6.1 unknown coord_net")
    add_hp_invalid("target_net TORV3", elem(ser_u8(NET_IPV4) + bytes.fromhex(IPV4_C["addr"]) + ser_u16be(8333) + ser_u8(NET_TORV3) + bytes.fromhex(ONION)), "R-6.1 unknown target_net")
    add_hp_invalid("I2P coordinator with non-zero port", elem(ser_holepunch_addr(dict(base, coord_net=NET_I2P, coord_addr=I2P, coord_port=1))), "I2P coord_port must be 0")
    add_hp_invalid("services without NODE_P2P_V2", elem(ser_holepunch_addr(base), services=NODE_NETWORK), "R-3.3 services lack NODE_P2P_V2")
    add_hp_invalid("empty addr", elem(b""), "R-6.1 invalid length")

    return {
        "bip": "tcp-holepunch",
        "version": "0.2.0",
        "feature_id": FEATURE_ID,
        "caps": CAPS,
        "holepunch_network_id": NET_HOLEPUNCH,
        "messages_valid": valid,
        "messages_invalid": invalid,
        "holepunch_elements_valid": hp_valid,
        "holepunch_elements_invalid": hp_invalid,
    }


def check(doc):
    for v in doc["messages_valid"]:
        payload = bytes.fromhex(v["hex"])
        dec = decode(v["kind"], payload)
        assert dec == v["decoded"], v["description"]
        assert MESSAGES[v["kind"]][0](dec) == payload, "re-encode " + v["description"]
    for v in doc["messages_invalid"]:
        try:
            decode(v["kind"], bytes.fromhex(v["hex"]))
        except Malformed:
            continue
        raise AssertionError("accepted invalid: " + v["description"])
    for v in doc["holepunch_elements_valid"]:
        payload = bytes.fromhex(v["element_hex"])
        dec = deser_addrv2_element(payload)
        assert dec == v["decoded"], v["description"]
        assert ser_addrv2_element(dec) == payload
        assert ser_holepunch_addr(dec["holepunch"]) == bytes.fromhex(dec["addr"])
    for v in doc["holepunch_elements_invalid"]:
        try:
            deser_addrv2_element(bytes.fromhex(v["element_hex"]))
        except Malformed:
            continue
        raise AssertionError("accepted invalid element: " + v["description"])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "vectors.json")
    doc = build()
    check(doc)
    if "--check" in sys.argv:
        with open(path) as f:
            on_disk = json.load(f)
        if on_disk != doc:
            raise SystemExit("vectors.json is out of date; rerun without --check")
        print("ok: %d valid messages, %d invalid messages, %d valid elements, %d invalid elements" % (
            len(doc["messages_valid"]), len(doc["messages_invalid"]),
            len(doc["holepunch_elements_valid"]), len(doc["holepunch_elements_invalid"])))
        return
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
