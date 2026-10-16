#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR BSD-2-Clause
"""Generate and verify test vectors for the coordinator-less TCP hole punching
BIP draft (v0.2).

Covers the `feature` payload, `PUNCHKEY` addrv2 elements (valid and invalid),
and the pairing computation of section 4: ECDH shared secret, pair value,
ranking, and role, for fixed keys and block hashes.

Encodings follow the draft: little-endian integers unless noted, BIP 155
address elements with big-endian ports, minimally encoded CompactSize,
compressed secp256k1 public keys, block hashes in internal byte order.

Usage:
    python3 gen_vectors.py            # writes vectors.json next to this file
    python3 gen_vectors.py --check    # verifies vectors.json round-trips
"""

import hashlib
import json
import os
import sys
from io import BytesIO

# BIP 155 network IDs
NET_IPV4, NET_IPV6, NET_TORV3, NET_I2P, NET_CJDNS, NET_PUNCHKEY = 1, 2, 4, 5, 6, 9
ADDR_LEN = {NET_IPV4: 4, NET_IPV6: 16}
PUNCHKEY_LENGTHS = {38, 50}
FEATURE_ID = "https://delvingbitcoin.org/t/2497/22"
PAIR_TAG = b"tcp-holepunch/pair"

NODE_P2P_V2 = 1 << 11
NODE_NETWORK = 1
NODE_WITNESS = 1 << 3


class Malformed(Exception):
    pass


# --- secp256k1 (affine, pure Python, for vectors only) -------------------------

FIELD_P = 2**256 - 2**32 - 977
ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GEN = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, FIELD_P - 2, FIELD_P) % FIELD_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, FIELD_P - 2, FIELD_P) % FIELD_P
    x3 = (lam * lam - x1 - x2) % FIELD_P
    return (x3, (lam * (x1 - x3) - y1) % FIELD_P)


def point_mul(pt, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
    return r


def lift_x(x):
    if x >= FIELD_P:
        return None
    y_sq = (pow(x, 3, FIELD_P) + 7) % FIELD_P
    y = pow(y_sq, (FIELD_P + 1) // 4, FIELD_P)
    if pow(y, 2, FIELD_P) != y_sq:
        return None
    return (x, y)


def pubkey_bytes(d):
    pt = point_mul(GEN, d)
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def parse_pubkey(b):
    """R-5.1: 33 bytes, prefix 0x02/0x03, x below the field size and on the curve."""
    if len(b) != 33 or b[0] not in (2, 3):
        raise Malformed("pubkey is not a compressed point (R-5.1)")
    pt = lift_x(int.from_bytes(b[1:], "big"))
    if pt is None:
        raise Malformed("pubkey x not on the curve or not below the field size (R-5.1)")
    if (pt[1] & 1) != (b[0] & 1):
        pt = (pt[0], FIELD_P - pt[1])
    return pt


def shared_x(d, pub):
    """R-4.4: x coordinate of d * P, 32 bytes big-endian."""
    s = point_mul(parse_pubkey(pub), d)
    if s is None:
        raise Malformed("shared point is infinity (R-4.4)")
    return s[0].to_bytes(32, "big")


def tagged_hash(tag, msg):
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + msg).digest()


def pair_value(x, block_hash_bytes):
    """R-4.5."""
    return tagged_hash(PAIR_TAG, x + block_hash_bytes)


def initiator_pubkey(pair, pub_a, pub_b):
    """R-4.7: the smaller key initiates if the lowest bit of the last byte is 0."""
    smaller, larger = sorted([pub_a, pub_b])
    return smaller if (pair[31] & 1) == 0 else larger


# --- primitives -----------------------------------------------------------------

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


# --- feature payload --------------------------------------------------------------

def ser_feature_data(m):
    return ser_u8(m["version"]) + ser_u32(m["flags"])


def deser_feature_data(payload):
    f = BytesIO(payload)
    version = read_exact(f, 1, "version")[0]
    flags = int.from_bytes(read_exact(f, 4, "flags"), "little")
    if f.read(1):
        raise Malformed("trailing bytes")
    return {"version": version, "flags": flags}


# --- PUNCHKEY addrv2 element --------------------------------------------------------

def ser_punchkey_addr(h):
    return ser_u8(h["net"]) + bytes.fromhex(h["addr"]) + bytes.fromhex(h["pubkey"])


def deser_punchkey_addr(b):
    if len(b) not in PUNCHKEY_LENGTHS:
        raise Malformed("invalid PUNCHKEY length %d (R-5.1)" % len(b))
    f = BytesIO(b)
    net = read_exact(f, 1, "net")[0]
    if net not in ADDR_LEN:
        raise Malformed("unknown net (R-5.1)")
    addr = read_exact(f, ADDR_LEN[net], "addr")
    pubkey = read_exact(f, 33, "pubkey")
    if f.read(1):
        raise Malformed("invalid PUNCHKEY length (R-5.1)")
    parse_pubkey(pubkey)
    return {"net": net, "addr": addr.hex(), "pubkey": pubkey.hex()}


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
    if net == NET_PUNCHKEY:
        el["punchkey"] = deser_punchkey_addr(addr)
        if not services & NODE_P2P_V2:
            raise Malformed("services lack NODE_P2P_V2 (R-5.1)")
        if port == 0:
            raise Malformed("port 0 (R-5.1)")
    return el


# --- fixtures -----------------------------------------------------------------------

IPV4_A = {"net": NET_IPV4, "addr": "cb007101", "port": 50123}       # 203.0.113.1, NAT-chosen port
IPV4_B = {"net": NET_IPV4, "addr": "c6336402", "port": 8335}        # 198.51.100.2
IPV6_A = {"net": NET_IPV6, "addr": "20010db8000000000000000000000001", "port": 18335}
ONION = "53cd5648af46a92b5b74b7f8f6bd3bb86e5d9ab77c5f0e03a5b43a1b4bbef6ac"
TIME = 1760600000
SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2

# secret keys (the first is BIP 340's test key 1, the others its test keys 2 and 3)
KEYS = {
    "A": 3,
    "B": 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
    "C": 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,
}
PUBS = {k: pubkey_bytes(d) for k, d in KEYS.items()}

# block hashes in display order (as shown by explorers and RPCs)
BLOCKS = {
    "genesis": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "block 1": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
}


def block_bytes(display_hex):
    return bytes.fromhex(display_hex)[::-1]


def first_x_off_curve():
    x = 1
    while lift_x(x) is not None:
        x += 1
    return x


def build():
    feature_valid, feature_invalid = [], []

    def add_feature_valid(desc, fields):
        payload = ser_feature_data(fields)
        assert deser_feature_data(payload) == fields
        feature_valid.append({"description": desc, "hex": payload.hex(), "decoded": fields})

    def add_feature_invalid(desc, payload_hex, reason):
        try:
            deser_feature_data(bytes.fromhex(payload_hex))
        except Malformed as e:
            feature_invalid.append({"description": desc, "hex": payload_hex, "reason": reason, "detected": str(e)})
            return
        raise SystemExit("invalid feature vector was accepted: " + desc)

    add_feature_valid("version 0, no flags", {"version": 0, "flags": 0})
    add_feature_valid("version 0, unknown high bit set (must be ignored)", {"version": 0, "flags": 1 << 31})
    add_feature_valid("version 1 (negotiates down to 0 with a version 0 peer, R-3.2)", {"version": 1, "flags": 0})
    add_feature_invalid("truncated flags", "0000", "missing bytes")
    add_feature_invalid("trailing byte", "000000000000", "trailing bytes")

    # PUNCHKEY elements
    el_valid, el_invalid = [], []

    def add_el_valid(desc, h, port, services=SERVICES):
        addr = ser_punchkey_addr(h)
        el = {"time": TIME, "services": services, "net": NET_PUNCHKEY, "addr": addr.hex(), "port": port}
        payload = ser_addrv2_element(el)
        decoded = deser_addrv2_element(payload)
        el_valid.append({"description": desc, "element_hex": payload.hex(), "addr_len": len(addr), "decoded": decoded})

    def add_el_invalid(desc, element_hex, reason):
        try:
            deser_addrv2_element(bytes.fromhex(element_hex))
        except Malformed as e:
            el_invalid.append({"description": desc, "element_hex": element_hex, "reason": reason, "detected": str(e)})
            return
        raise SystemExit("invalid PUNCHKEY vector was accepted: " + desc)

    def pk(target, who):
        return {"net": target["net"], "addr": target["addr"], "pubkey": PUBS[who].hex()}

    add_el_valid("IPv4 announcer, key A (38 bytes)", pk(IPV4_A, "A"), IPV4_A["port"])
    add_el_valid("IPv4 announcer, key B (38 bytes)", pk(IPV4_B, "B"), IPV4_B["port"])
    add_el_valid("IPv6 announcer, key C (50 bytes)", pk(IPV6_A, "C"), IPV6_A["port"])
    add_el_valid("same key announced for both families (R-4.2)", pk(IPV6_A, "A"), IPV6_A["port"])

    base = pk(IPV4_A, "A")

    def elem(addr_bytes, services=SERVICES, port=IPV4_A["port"]):
        return ser_addrv2_element({"time": TIME, "services": services, "net": NET_PUNCHKEY, "addr": addr_bytes.hex(), "port": port}).hex()

    add_el_invalid("length 39 (trailing byte in addr)", elem(ser_punchkey_addr(base) + b"\x00"), "R-5.1 invalid length")
    add_el_invalid("length 37 (truncated pubkey)", elem(ser_punchkey_addr(base)[:-1]), "R-5.1 invalid length")
    add_el_invalid("length 38 with net IPV6 (truncated)", elem(ser_u8(NET_IPV6) + bytes.fromhex(IPV4_A["addr"]) + PUBS["A"]), "R-5.1 truncated")
    add_el_invalid("length 50 with net IPV4 (padded)", elem(ser_punchkey_addr(base) + b"\x00" * 12), "R-5.1 invalid length")
    add_el_invalid("net TORV3", elem(ser_u8(NET_TORV3) + bytes.fromhex(ONION) + b"\x00" * 5), "R-5.1 unknown net")
    add_el_invalid("pubkey with prefix 0x04", elem(ser_u8(NET_IPV4) + bytes.fromhex(IPV4_A["addr"]) + b"\x04" + PUBS["A"][1:]), "R-5.1 not a compressed point")
    add_el_invalid("pubkey x not below the field size", elem(ser_u8(NET_IPV4) + bytes.fromhex(IPV4_A["addr"]) + b"\x02" + FIELD_P.to_bytes(32, "big")), "R-5.1 invalid point")
    add_el_invalid("pubkey x not on the curve", elem(ser_u8(NET_IPV4) + bytes.fromhex(IPV4_A["addr"]) + b"\x02" + first_x_off_curve().to_bytes(32, "big")), "R-5.1 invalid point")
    add_el_invalid("services without NODE_P2P_V2", elem(ser_punchkey_addr(base), services=NODE_NETWORK), "R-5.1 services lack NODE_P2P_V2")
    add_el_invalid("port 0", elem(ser_punchkey_addr(base), port=0), "R-5.1 port 0")
    add_el_invalid("empty addr", elem(b""), "R-5.1 invalid length")

    # pairing: shared secret, pair value, role (R-4.4 to R-4.7)
    pairing = []
    names = sorted(KEYS)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            x_ab = shared_x(KEYS[a], PUBS[b])
            x_ba = shared_x(KEYS[b], PUBS[a])
            assert x_ab == x_ba, "ECDH is symmetric"
            for bname, bhex in BLOCKS.items():
                pv = pair_value(x_ab, block_bytes(bhex))
                init = initiator_pubkey(pv, PUBS[a], PUBS[b])
                pairing.append({
                    "parties": [a, b],
                    "secret_%s" % a: "%064x" % KEYS[a],
                    "secret_%s" % b: "%064x" % KEYS[b],
                    "pubkey_%s" % a: PUBS[a].hex(),
                    "pubkey_%s" % b: PUBS[b].hex(),
                    "shared_x": x_ab.hex(),
                    "block": bname,
                    "block_hash_display": bhex,
                    "block_hash_bytes": block_bytes(bhex).hex(),
                    "pair": pv.hex(),
                    "role_bit": pv[31] & 1,
                    "initiator": a if init == PUBS[a] else b,
                })

    # ranking: node A holds entries for B and C (R-4.6, R-7.4)
    ranking = []
    for bname, bhex in BLOCKS.items():
        rows = []
        for other in ("B", "C"):
            pv = pair_value(shared_x(KEYS["A"], PUBS[other]), block_bytes(bhex))
            rows.append({"entry": other, "pair": pv.hex(), "role_of_A": "initiator" if initiator_pubkey(pv, PUBS["A"], PUBS[other]) == PUBS["A"] else "responder"})
        rows.sort(key=lambda r: int(r["pair"], 16))
        ranking.append({"node": "A", "block": bname, "block_hash_display": bhex, "order": rows})

    return {
        "bip": "tcp-holepunch-coordinatorless",
        "version": "0.2.0",
        "feature_id": FEATURE_ID,
        "punchkey_network_id": NET_PUNCHKEY,
        "pair_tag": PAIR_TAG.decode(),
        "feature_valid": feature_valid,
        "feature_invalid": feature_invalid,
        "punchkey_elements_valid": el_valid,
        "punchkey_elements_invalid": el_invalid,
        "pairing": pairing,
        "ranking": ranking,
    }


def check(doc):
    for v in doc["feature_valid"]:
        payload = bytes.fromhex(v["hex"])
        dec = deser_feature_data(payload)
        assert dec == v["decoded"], v["description"]
        assert ser_feature_data(dec) == payload
    for v in doc["feature_invalid"]:
        try:
            deser_feature_data(bytes.fromhex(v["hex"]))
        except Malformed:
            continue
        raise AssertionError("accepted invalid: " + v["description"])
    for v in doc["punchkey_elements_valid"]:
        payload = bytes.fromhex(v["element_hex"])
        dec = deser_addrv2_element(payload)
        assert dec == v["decoded"], v["description"]
        assert ser_addrv2_element(dec) == payload
        assert ser_punchkey_addr(dec["punchkey"]) == bytes.fromhex(dec["addr"])
    for v in doc["punchkey_elements_invalid"]:
        try:
            deser_addrv2_element(bytes.fromhex(v["element_hex"]))
        except Malformed:
            continue
        raise AssertionError("accepted invalid element: " + v["description"])
    for v in doc["pairing"]:
        a, b = v["parties"]
        da = int(v["secret_" + a], 16)
        db = int(v["secret_" + b], 16)
        pa = bytes.fromhex(v["pubkey_" + a])
        pb = bytes.fromhex(v["pubkey_" + b])
        assert pubkey_bytes(da) == pa and pubkey_bytes(db) == pb
        x = shared_x(da, pb)
        assert x == shared_x(db, pa) == bytes.fromhex(v["shared_x"])
        bh = bytes.fromhex(v["block_hash_bytes"])
        assert bh[::-1].hex() == v["block_hash_display"]
        pv = pair_value(x, bh)
        assert pv.hex() == v["pair"], "pair value"
        assert (pv[31] & 1) == v["role_bit"]
        assert initiator_pubkey(pv, pa, pb) == (pa if v["initiator"] == a else pb)
    for r in doc["ranking"]:
        values = [int(row["pair"], 16) for row in r["order"]]
        assert values == sorted(values)


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
        print("ok: %d feature, %d invalid feature, %d elements, %d invalid elements, %d pairings, %d rankings" % (
            len(doc["feature_valid"]), len(doc["feature_invalid"]),
            len(doc["punchkey_elements_valid"]), len(doc["punchkey_elements_invalid"]),
            len(doc["pairing"]), len(doc["ranking"])))
        return
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
