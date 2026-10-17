```
  BIP: ?
  Layer: Peer Services
  Title: Coordinator-less TCP Hole Punching for Peer Connections
  Authors: TBD
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-10-16: https://delvingbitcoin.org/t/tcp-hole-punching-for-bitcoin-nodes-behind-home-nats/2497/22
  Version: 0.3.1
  Requires: 155, 324, 434
```

## Abstract

Two nodes behind home NATs can connect to each other if both send a SYN
to the other at about the same time and both NATs give connections from
one local port a stable external port. This document lets nodes do that
without anyone telling them whom to connect to or when.

A node sends every outbound connection from one fixed local port, the
*punch port*, and learns its external address from what peers echo back
in `version`. It announces that address together with a short-lived
public key as a new address type that travels over ordinary address
relay, and keeps the announcements it receives from others. Every new
block starts a *round*: for each stored announcement the node derives a
*pair value* from the ECDH shared secret of the two keys and the block
hash, and connects from its punch port to the few announcers with the
lowest values. Both nodes of a pair derive the same value, so they tend
to choose each other in the same round, and because the block did not
exist when the keys were published, nobody can choose a key in order to
be picked. No message is exchanged before the SYNs cross.

## Copyright

This BIP is licensed under the BSD-2-Clause License. Auxiliary code in
`bip-tcp-holepunch-coordinatorless/` is additionally licensed under the
MIT License.

## Motivation

Most Bitcoin nodes on home connections sit behind a NAT and never accept
an inbound connection. They use inbound slots of reachable nodes and
offer none, and automatic port mapping has not changed that noticeably.
TCP hole punching lets two such nodes connect directly. Roughly two
thirds of home IPv4 NATs behave the way it needs, and IPv6 at home
usually means no NAT and only a stateful firewall, which the same
procedure passes[^numbers].

Hole punching needs two things: each node must know the other's external
address and port, and both must connect at about the same moment. Every
design so far takes both from a coordinator, a third node or a Tor
service that introduces the two. The coordinator learns who connects to
whom, can refuse, and is one more thing to run. This document takes the
address from address relay, which every node already does, and the
moment from the next block, which every node sees within seconds of
every other.

Connections made this way are extra, best-effort connections for nodes
that have none to offer today. Nothing about ordinary connections
changes.

## Scope

This document covers pairs of nodes whose NAT or firewall maps every
outbound connection from one local port to the same external port
(endpoint-independent mapping in the sense of RFC 4787). A node with a
stateful firewall and no NAT qualifies. Symmetric NATs, carrier-grade
NAT, and most mobile networks do not; a node that detects such a mapping
does not take part. How the NAT filters inbound packets does not matter,
because each side sends to the other before the other's SYN arrives.

Taking part is opt-in. A node that does not opt in is unaffected. A node
in initial block download holds no rounds.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

Integers are little-endian unless the name ends in `_be`. `CompactSize`
is the P2P protocol's variable-length integer, minimally encoded.

**Endpoint.** An address and port, encoded as a BIP 155 address element
without `time` and `services`:

| Type          | Name       | Description |
|---------------|------------|-------------|
| `uint8`       | `net`      | `IPV4` (1) or `IPV6` (2) |
| `CompactSize` | `addr_len` | 4 or 16 |
| `uint8[]`     | `addr`     | address bytes |
| `uint16_be`   | `port`     | port, big-endian as in BIP 155 |

**Punch port.** One local TCP port per address family, used for every
outbound clearnet connection and for punching. It is chosen at random
from 49152 to 65535 when the node starts, skipping ports the
implementation treats as bad, is configurable, and never changes while
the node runs[^punch-port].

**Punch socket.** A TCP socket bound to the punch port with
`SO_REUSEADDR` and `SO_REUSEPORT` set before binding.

**Report.** The `addr_recv` field of a peer's `version` message: the
node's address and port as that peer sees them. Only reports on outbound
connections made from a punch socket without a proxy count, and such
peers are *reporting peers*.

**External address.** For one address family, the endpoint that at least
two current reporting peers in different network groups report, as long
as no two reporting peers in different groups report another one.

**Network group.** The grouping the implementation uses for outbound
peer diversity, such as /16 for IPv4, /32 for IPv6, or autonomous
systems.

**Source group.** The network group of the peer an announcement arrived
from, taken from that peer's TCP address.

**Key.** A secp256k1 key pair the node holds for this protocol, one per
address family it announces: a secret `p` and `P = p·G`, with `P`
serialized as a 33-byte compressed point.

**Entry.** A stored announcement: its endpoint, its public key, the
element's `time`, the local time the node first received that endpoint
and key together (`received_at`), the local time it last received them
(`last_seen`), the shared secret (R-4.4), and the source group.

**Pair value.** A 256-bit value derived from two nodes' keys and a block
hash (R-4.5). The two nodes compute the same value; nobody else can.

**Round.** The evaluation of the table that one new block triggers
(section 7).

**Roles.** Each session has an *initiator* and a *responder* in the sense
of BIP 324: the initiator sends the first bytes. The role comes from the
pair value (R-4.7), never from whether the socket came out of `connect()`
or `accept()`.

**Session.** The state of one attempt, keyed by (punch port, peer
endpoint), started by a pick (R-7.4).

## Specification

### 1. Sockets

- R-1.1 Every outbound connection to an `IPV4` or `IPV6` peer that is not
  made through a proxy MUST be made from a punch socket of that family.
  If the operating system refuses because the 4-tuple is still in use,
  usually `TIME_WAIT` after a recent connection to the same peer, the node
  MAY use an ephemeral port; that connection is not a reporting peer.
- R-1.2 The node MUST listen on each punch port. A connection accepted
  there is a punched connection and nothing else.
- R-1.3 Punch attempts are non-blocking connects from punch sockets. An
  attempt that is superseded MUST be closed.
- R-1.4 IPv4-mapped IPv6 addresses MUST NOT appear in endpoints, reports,
  announcements, or connect targets. Punch sockets SHOULD be bound to a
  stable local address; IPv6 temporary addresses make reports disagree.

### 2. External address

- R-2.1 Reports from proxied connections, from connections not made from
  a punch socket, with an address that is not globally routable, or with
  port 0 MUST be ignored.
- R-2.2 The node has an external address for a family when at least two
  current reporting peers in different network groups report the same
  endpoint. A single dissenting report changes nothing.
- R-2.3 If two such sets report different endpoints, the node's mapping is
  not endpoint-independent or it has several addresses. It then has no
  external address for that family and MUST NOT announce until R-2.2
  yields one endpoint again.
- R-2.4 Losing the external address stops new announcements and new picks
  for that family. Sessions already running continue.
- R-2.5 On test networks where all nodes share a host, an implementation
  MAY waive routability (R-2.1, R-5.1, R-7.3) and treat every peer as its
  own network group.

### 3. Signalling

- R-3.1 Support is signalled per connection with a BIP 434 `feature`
  message. The `featureid` is `https://delvingbitcoin.org/t/2497/22`
  until a BIP number is assigned, then `BIP<n>`. The `featuredata` is:

  | Type     | Name      | Description |
  |----------|-----------|-------------|
  | `uint8`  | `version` | highest version the sender supports; 0 for this document |
  | `uint32` | `flags`   | none defined; send 0, ignore unknown bits |

  The feature means "send me `PUNCHKEY` elements". It does not say
  whether the sender announces itself. A node MUST NOT send `PUNCHKEY`
  elements to a peer that did not send the feature, and processes
  elements from any peer that sends them.
- R-3.2 The version in use on a connection is the lower of the two
  announced. A node that supports version N MUST support every lower
  defined version. Only version 0 is defined[^min-version].
- R-3.3 Participating nodes MUST advertise `NODE_P2P_V2`.
- R-3.4 The feature SHOULD NOT be sent on a connection that closes right
  after the handshake, such as a feeler: nothing is relayed on it, and
  the feature would only tell one more node that the sender takes part.
- R-3.5 This document defines no new message. The only new wire element
  is the `PUNCHKEY` address type.

### 4. Keys and the pair value

- R-4.1 When it starts, a participating node generates a secp256k1 key
  pair from fresh randomness for each address family it may announce: a
  uniformly random secret `p` in `[1, n-1]` and `P = p·G`. A key MUST NOT
  be derived from or shared with any other key, including the node's key
  for the other family, and is used for nothing but this protocol.
- R-4.2 A node has one current key per address family. The IPv4 and IPv6
  keys of one node are independent, and nothing in the protocol links
  them[^key-per-family].
- R-4.3 A family's key MUST be replaced when that family's external
  address changes, so that a new address is never announced under a key
  that was seen with an old one, and at least every `KEY_ROTATE_H`
  (24 h), at a time not aligned across nodes and not aligned with the
  node's other family[^rotation]. After replacement the node uses the new
  key only, MAY discard the old secret, and SHOULD announce that family
  again promptly (R-5.4).
- R-4.4 The **shared secret** between the node and an entry is `x`, the x
  coordinate of `p · P_entry` as 32 bytes big-endian, where `p` is the
  node's key for the entry's address family. The other node computes
  `p_entry · P` with its own key for that family and gets the same `x`. If the product is the
  point at infinity the entry MUST be ignored.
- R-4.5 The **pair value** of an entry for a block is

  ```
  pair = TaggedHash("tcp-holepunch/pair", x || block_hash)
  ```

  with `TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` as
  in BIP 340, and `block_hash` the block's header hash in the byte order
  of the `prev_block` field of a header, which is the reverse of the hex
  shown by explorers.
- R-4.6 Pair values are **ranked** as 256-bit unsigned integers, first
  byte most significant, lower first.
- R-4.7 The **role** follows from the pair value: let `bit` be the lowest
  bit of the last byte of `pair`. The node with the lexicographically
  smaller compressed public key is the initiator if `bit` is 0 and the
  responder if `bit` is 1; the other node takes the other
  role[^coin-flip].

### 5. Announcements: the `PUNCHKEY` address type

This document reserves BIP 155 network ID `0x09`, enumeration
`PUNCHKEY`. The `addr` field is:

| Type        | Name     | Description |
|-------------|----------|-------------|
| `uint8`     | `net`    | `IPV4` (1) or `IPV6` (2) |
| `uint8[]`   | `addr`   | the announcer's external address, 4 or 16 bytes |
| `uint8[33]` | `pubkey` | the announcer's current public key, compressed |

The element's `port` is the external port, `services` the announcer's
services (MUST include `NODE_P2P_V2`), and `time` the time of the
announcement. Valid `addr` lengths are 38 and 50 bytes.

- R-5.1 A receiver MUST reject an element with an invalid length, a `net`
  other than `IPV4` or `IPV6`, an `addr` that is not globally routable, a
  `port` of 0, a `pubkey` that is not a valid compressed point (prefix
  other than `0x02` or `0x03`, x coordinate not below the field size, or
  x not on the curve), `services` without `NODE_P2P_V2`, or a `time`
  outside `now - ENTRY_TTL < time <= now + FUTURE_SKEW` (2 h and 10 min).
  A rejected element is ignored; rejection alone is no reason to
  disconnect.
- R-5.2 `PUNCHKEY` elements MUST NOT be added to the address manager,
  persisted, or returned in response to `getaddr`. Accepted elements go
  to the table of section 6.
- R-5.3 An element MAY be relayed to at most `RELAY_FANOUT` (2) peers that
  sent the feature and `sendaddrv2`, only if `now - RELAY_TTL < time`
  (10 min), never back to the peer it came from, with the
  implementation's usual address relay timing and with `time` preserved.
  A node relays only elements it stored or refreshed, and a given
  (endpoint, `pubkey`) at most once per `RELAY_TTL`. Elements are sent
  alone or in an `addrv2` message of at most ten elements.
- R-5.4 A node announces, per address family, only while it has an
  external address whose port is not one it would treat as a bad port
  itself, and a free hole-punch outbound slot (section 9) or a free
  inbound slot, counting slots reserved by sessions as
  used[^both-announce]. The element carries the family's current key and
  `time = now`. It goes to every peer that sent the feature, at most once
  per `ANNOUNCE_INTERVAL` (30 min) per peer, and once more promptly after
  the key or the address changes. A node announces one element per family
  at a time.
- R-5.5 A node MUST NOT process more than `PUNCHKEY_PER_HOUR` (120)
  elements from one peer in any hour, counting every element received
  whether or not it is accepted. Further elements from that peer in that
  hour are ignored, which is not by itself a protocol violation, and a
  node SHOULD NOT send a peer more than that[^rate-limit]. Elements also
  count as one address each against the general address rate limit.
- R-5.6 A node ignores elements that carry one of its own public keys or
  one of its own external addresses.

### 6. The table

The table is organised by the peer an element arrived from, the one
thing about an element that cannot be faked. Nothing in it is keyed by a
value the announcer chooses[^source-cap].

- R-6.1 Entries are identified by (endpoint, `pubkey`). The shared secret
  is computed once, when the entry is stored. Receiving an element for a
  stored (endpoint, `pubkey`) refreshes the entry: `last_seen` becomes the
  current time, `time` the larger of the two, and `received_at` stays. A
  different `pubkey` for a stored endpoint, or a different endpoint for a
  stored `pubkey`, is a distinct entry.
- R-6.2 A node keeps at most `SOURCE_CAP` (128) entries per source group.
  To store a new entry for a full group it evicts an expired entry of that
  group if there is one, otherwise one chosen uniformly at
  random[^random-eviction]. A refresh evicts nothing.
- R-6.3 A node keeps at most `TABLE_MAX` (4096) entries in total. To store
  a new entry in a full table it evicts an expired entry if there is one,
  otherwise one chosen uniformly at random from the source group with the
  most entries.
- R-6.4 An entry expires `ENTRY_TTL` (2 h) after its
  `last_seen`[^last-seen]. Expired entries take no part in rounds and MAY
  be removed at any time.
- R-6.5 An entry is removed when a round picks it (R-7.6).
- R-6.6 The table is not persisted; a restart begins with an empty table.

### 7. Rounds

- R-7.1 A round starts when the node's active chain tip changes to a
  block `B` at a greater height than before and the node is not in
  initial block download. A tip change that does not increase the height,
  such as a reorganisation to a chain of equal length, holds no
  round[^reorg]. Each block hash triggers at most one round. The round
  starts at the time of the tip change, and the node remembers that time
  for each of its recent tips[^block-trigger].
- R-7.2 An entry takes part in the round for `B` only if its
  `received_at` is earlier than the time the tip reached `B`'s
  parent[^parent]. If the tip reached `B`'s parent before the node's
  current run, no entry takes part.
- R-7.3 An eligible entry is a *candidate* if all of the following hold:
  - it has not expired, and the node has a punch port and an external
    address for its address family;
  - its endpoint is globally routable, is not one of the node's own
    addresses or external addresses, and its port is not one the
    implementation treats as a bad port;
  - the node has no connection and no session to the endpoint, and no
    session with an entry carrying the same `pubkey`;
  - fewer than `GROUP_SESSIONS_PER_HOUR` (4) sessions to addresses in its
    network group started in the last hour;
  - with the role from R-4.7 for this round: as initiator, the hole-punch
    outbound slot is free and the endpoint passes the node's outbound
    network-group diversity rules; as responder, an inbound slot is free.
    Reserved slots count as used.

  The address, port, and network group checked here are the announced
  ones and cannot be verified before the attempt. They need not be: the
  node sends its SYN to exactly the endpoint it evaluated, so a false
  announcement costs one session's attempts and nothing else.
- R-7.4 The node computes the pair value (R-4.5) of every candidate for
  `B`, sorts the candidates by it (R-4.6), and walks the list from the
  lowest value. It skips a candidate whose network group or source group
  equals that of a candidate already taken this round[^one-ticket], and
  one whose role's slot was reserved meanwhile. It stops after
  `PICKS_PER_ROUND` (3) picks, or earlier when another session would
  exceed `MAX_ACTIVE_SESSIONS` (6)[^ranking]. For each pick it reserves
  the slot the role needs until the session ends and starts a session
  (section 8) with the entry's endpoint and the round's start time. A
  node with neither a free hole-punch outbound slot nor a free inbound
  slot skips the round.
- R-7.5 No attempt is made outside a round, and no entry is attempted
  more than once per announcement.
- R-7.6 A picked entry is removed from the table whatever the outcome. It
  comes back only with a new announcement, which then waits for R-7.2
  again.

### 8. Punching

- R-8.1 On a pick the node opens a punch socket and calls `connect()` on
  the entry's endpoint, with a deadline `WINDOW_MS` (120000 ms) after the
  session start. It leaves the attempt pending: the operating system
  retransmits the SYN, and the pending attempt keeps the NAT mapping
  towards the peer alive[^window]. At the deadline it MUST close a pending
  attempt and start no more, but keeps accepting a matching socket on the
  punch port until the session ends (R-8.7).
- R-8.2 If an attempt fails before the deadline, for any reason including
  the operating system giving up, the node MUST close the socket, wait
  `RETRY_MS` (1000 ms) doubled after each failure, and connect again. One
  attempt at a time per session; with these numbers at most seven.
- R-8.3 An attempt that fails because the 4-tuple is already in use is
  closed and not retried; the node waits for a matching socket from the
  listener until the session ends.
- R-8.4 The session's connection is the first socket whose remote endpoint
  equals the entry's endpoint, whether it came from `connect()` or from
  `accept()` on the punch port; with fixed ports on both sides there can
  be only one. A socket accepted on the punch port that matches no session
  is *held*: nothing is read from or written to it, it becomes the
  session's connection if a session for its endpoint starts within
  `HOLD_MS` (10000 ms), and it is closed otherwise. At most `HELD_MAX` (8)
  sockets are held; the oldest is closed to make room[^hold].
- R-8.5 On establishment the node stops its attempts. The initiator sends
  its BIP 324 initiator bytes at once. The responder sends nothing until
  bytes arrive; if its connection is closed before any byte arrived, the
  peer was not ready yet, the session goes on, and the responder resumes
  attempts under R-8.1 and R-8.2. A connection closed after bytes were
  exchanged ends the session as a failure.
- R-8.6 The connection MUST use the BIP 324 v2 transport. A v1 prefix
  MUST close it; there is no fallback. The usual `version`/`verack`
  handshake follows, the initiator sending `version` first.
- R-8.7 The session ends in success when `verack` has been received, or in
  failure `WINDOW_MS + GRACE_MS` (125000 ms) after the session start
  without it; handshake progress does not extend that deadline. On failure
  every socket of the session is closed and the reserved slot released.
  Nothing is reported to anyone, and nothing is retried until the peer
  announces again.
- R-8.8 Both nodes start their sessions when their own tip reaches `B`, so
  their start times differ by the difference in block propagation and
  validation, usually seconds. Because both attempts stay pending, the two
  SYNs only have to cross once anywhere in the overlap of the two windows;
  the first SYN to reach a NAT that has no mapping yet is dropped and
  retransmitted. No clock is involved. R-1.1 keeps the mapping alive
  between sessions, and the pending attempt keeps it alive towards the
  peer.

### 9. Slots

- R-9.1 The initiator accounts the connection as a *hole-punch outbound*,
  one slot beyond its ordinary automatic outbound slots
  (`HP_OUTBOUND_MAX` = 1), never an anchor and not counted when deciding
  whether outbound connectivity is diverse enough to record address
  manager failures[^extra-slot]. The responder accounts it as inbound.

### 10. Invariants

| ID | Invariant | Test shape |
|----|-----------|------------|
| I-1 | Each session has exactly one initiator, given by the pair value; it sends the first bytes (BIP 324 key, then `version`), and the responder sends nothing before receiving BIP 324 bytes. | Two nodes with known keys and a chosen block; capture first bytes; swap in a block with the other role bit. |
| I-2 | A session is keyed by (punch port, peer endpoint) and has at most one connection, whose remote endpoint equals the entry's endpoint. An accepted socket that matches no session is held untouched for at most `HOLD_MS`, then closed unless a session for its endpoint started; at most `HELD_MAX` are held. | Connect to the punch port unexpectedly; assert silence and closure after `HOLD_MS`. Connect, then start a session for that endpoint; assert it uses the held socket. |
| I-3 | Every non-proxied clearnet outbound connection, every punch attempt, and the listener of a family share the punch port, except connections that fell back under R-1.1, which do not report. | Inspect local ports of all sockets. |
| I-4 | SYNs go only to endpoints of entries picked in a round: routable, not local, not the node's own, same family, not a bad port; one attempt at a time; at most seven per session. | Feed elements with bad endpoints; count SYNs with a socket mock. |
| I-5 | Per round at most `PICKS_PER_ROUND` sessions start, at most one per source group and one per network group; at most `MAX_ACTIVE_SESSIONS` exist; at most `GROUP_SESSIONS_PER_HOUR` start per network group per hour. | Fill the table from one peer and from several; connect blocks; count sessions per source and per group. |
| I-6 | Every session ends within `WINDOW_MS + GRACE_MS` in success or failure, releasing every socket but the connection and the reserved slot. | Drive sessions to both outcomes; compare socket counts. |
| I-7 | `PUNCHKEY` elements never enter the address manager, `getaddr` responses, or persisted files; they are relayed only within `RELAY_TTL`, at most once per `RELAY_TTL` per entry, and only to peers that sent the feature and `sendaddrv2`; at most `PUNCHKEY_PER_HOUR` per peer are processed. | Send elements; query the address manager and `getaddr`; exceed the per-peer rate; restart. |
| I-8 | A hole-punch outbound exists only as the initiator side of a session with a picked entry that passed outbound diversity; at most `HP_OUTBOUND_MAX`; never an anchor. | Entry in an existing outbound's group: assert no initiator session. |
| I-9 | Punched connections use BIP 324 without v1 fallback; both nodes advertise `NODE_P2P_V2`. | Send a v1 `version` on a punched connection; assert close. |
| I-10 | The node has an external address only while two reporting peers in different network groups agree and no second such set disagrees; it announces only with an external address, its current key, and a free slot of either kind; a pick reserves the slot its role needs. | One dissenting report: address kept. Two agreeing dissenters: address dropped, no announcement. Both slots taken: no announcement, no picks. |
| I-11 | No source group exceeds `SOURCE_CAP` and the table never exceeds `TABLE_MAX`; a full group evicts at random within itself, a full table evicts from its largest group, a refresh evicts nothing; an entry learned through one peer is never displaced by another peer's elements; a re-received entry keeps `received_at`; a picked entry is removed. | Flood from one peer with distinct addresses and keys; count that peer's entries; check other peers' entries are untouched. Re-send a stored element; assert eligibility unchanged. |
| I-12 | Each family has its own key, replaced whenever that family's announced external address changes and at least every `KEY_ROTATE_H`, at a time independent of the other family's; a new address is never announced under a key seen with an old one; pair values use the current key of the entry's family only. | Change the reported IPv4 address; assert a new IPv4 key is announced, the IPv6 key is unchanged, and the old key never appears with the new address. |
| I-13 | An entry takes part only in rounds for blocks whose parent the tip reached after the entry was first received; the pair value depends on that block's hash. | Insert an entry, connect one block: no attempt. Connect another: attempt. Change the block hash: different pick. |

### 11. Limits

| Name | Default | Used in |
|------|---------|---------|
| punch port | random in 49152 to 65535, fixed per run | Terminology |
| `WINDOW_MS` | 120000 | R-8.1 |
| `RETRY_MS` | 1000, doubled after each failure | R-8.2 |
| `GRACE_MS` | 5000 | R-8.7 |
| `HOLD_MS` / `HELD_MAX` | 10000 / 8 | R-8.4 |
| `PICKS_PER_ROUND` | 3, at most one per source group and per network group | R-7.4 |
| `MAX_ACTIVE_SESSIONS` | 6 | R-7.4 |
| `GROUP_SESSIONS_PER_HOUR` | 4 | R-7.3 |
| `SOURCE_CAP` | 128 | R-6.2 |
| `TABLE_MAX` | 4096 | R-6.3 |
| `PUNCHKEY_PER_HOUR` | 120 | R-5.5 |
| `ENTRY_TTL` | 2 h | R-5.1, R-6.4 |
| `RELAY_TTL` / `FUTURE_SKEW` | 10 min / 10 min | R-5.1, R-5.3 |
| `RELAY_FANOUT` | 2 | R-5.3 |
| `ANNOUNCE_INTERVAL` | 30 min | R-5.4 |
| `KEY_ROTATE_H` | 24 h | R-4.3 |
| `HP_OUTBOUND_MAX` | 1 | R-9.1 |

## Rationale

[^numbers]: A survey among developers in the discussion thread found
endpoint-independent mapping in about two thirds of home IPv4
environments and no NAT at all on IPv6. Measurements of libp2p's DCUtR,
which does TCP simultaneous open with a relay as coordinator, report
about 70% success over millions of attempts.

[^punch-port]: One port for every outbound connection means every peer
reports the same mapping, every outbound connection keeps that mapping
alive, and no probe connections are needed. The port is random rather
than fixed because a port-preserving NAT shows the local port to the
world, so a fixed number would mark the node's traffic to any observer,
and because two nodes behind one NAT would otherwise ask for the same
port. Peers never need to know it: they see only the mapped port, and
the node learns that from their reports.

[^min-version]: Taking the lower version lets an upgrade spread one node
at a time. Old nodes will read this field the way it is defined now, so
the rule cannot change later.

[^rotation]: Announcements go to the whole network and tie a key to an
address. Home addresses change, and a key that outlived the change would
let anyone follow the node from one address to the next, which nothing
else lets them do for an unreachable node. So a new address never
appears under an old key. Rotating more often than that would hurt:
every new key is a new entry in every table that waits a block before it
can be picked (R-7.2), while picks of the old key go unanswered.

[^key-per-family]: Nothing else in the P2P protocol links a node's IPv4
and IPv6 addresses, and announcing both under one key would link them
for everyone who collects announcements. So each family has its own key,
and the two rotate at independent times, since two keys that always
change together are linked by that alone. The cost is small: one more
key to hold, one more pair value per dual-stack peer, and the chance
that a pair is picked over both families in one round and ends up with
two connections, one per family. That is rare and costs a slot on each
side.

[^coin-flip]: The initiator needs the single hole-punch outbound slot and
the responder an inbound slot. A fixed rule such as "the smaller key
initiates" would tie each pair to one combination for good, and a node
whose outbound slot is taken could never connect to half of its
candidates. Deriving the role from the pair value gives every pair a
fresh coin flip each round.

[^both-announce]: With no coordinator there is nobody to ask for an
introduction. A node that only wants outbound connections still has to
be in other nodes' tables, so it announces too. A node with no free slot
of either kind stops announcing and ages out of every table.

[^rate-limit]: An honest peer originates a few elements an hour and
forwards a bounded trickle of others'. The limit is sized to the table:
a peer's `SOURCE_CAP` entries turn over once per `ENTRY_TTL`, which is 64
an hour, and twice that leaves room for refreshes. Rejected elements
count so that a stream of invalid keys spends the sender's budget rather
than the receiver's processor.

[^source-cap]: The announced address is whatever the announcer wrote, so
bounding by it would let one peer claim a thousand network groups for
free. The peer an element arrived from is real. A cap per source bounds
what one peer can plant, however many addresses or keys it invents, and
lets it displace only its own entries; filling more of the table means
being more of the node's peers from more network groups. Admission
therefore says nothing about whether the stored addresses are diverse,
since their groups may be invented; that is checked at pick time
(R-7.3), where a lie costs one wasted SYN.

[^random-eviction]: For a full group, refusing the newcomer would let a
peer fill the group once and hold it for good by refreshing, so nothing
honest learned through that peer would be stored again. Evicting the
oldest would let a flood of new entries clear out everything that came
before it. Evicting at random degrades gracefully: each insertion evicts
entries in proportion to how many the inserter already holds, so a flood
mostly evicts itself, an honest newcomer always gets in, and an honest
entry survives each insertion with probability 1 - 1/`SOURCE_CAP`. At the
table ceiling, evicting from the largest group hits exactly the groups a
flood inflates.

[^last-seen]: Expiring from the local time of the last receipt trusts
nothing the announcer wrote. The announced `time` only gates relay, so a
stale element stops spreading.

[^reorg]: Nodes see a reorganisation to a chain of the same height at
different times or not at all, so a round on it would rarely find both
sides on the same block. Height advances in the same order everywhere.

[^block-trigger]: A new block is the one event every node sees within
seconds of every other, without any clock. Header timestamps are set by
miners and may be off by hours; rounds at fixed wall-clock times would
need clocks to agree, and a node with a wrong clock would punch alone
without noticing. The window absorbs the variance in when nodes connect
a block. A node catching up after being offline holds a round for each
block it connects, which nobody else is evaluating; the session cap
bounds that waste and the node is in step again at the next block.

[^parent]: The pair value is unpredictable only if the block did not
exist when the key was chosen. It is not enough to require the block to
arrive after the entry: whoever sees a block a second earlier than the
victim, which is ordinary propagation variance, can try keys against the
known hash for that second and still deliver the announcement first. A
commodity machine tries a few hundred thousand keys a second, enough to
land in the lowest three of a thousand. Requiring the entry to predate
the moment the tip reached the block's *parent* puts a whole block
interval between the last possible key choice and the first knowledge
of the hash; only a miner withholding two consecutive blocks could
grind, at a cost far beyond the prize. `received_at` is the node's own
clock, so it cannot be backdated. Tor's onion service directories use
the same ordering, a public random value fixed only after the keys it
is combined with, for the same reason.

[^one-ticket]: The pair value is the selection signal, so a peer that
plants many entries holds many tickets, and the best of a hundred draws
beats the best of a few almost every round. That cannot be fixed at the
ranking, because the ranking is what makes both sides agree. Taking at
most one pick per source group per round caps what one peer's entries
can cost at one pick in three, however many it planted. In the honest
case the cap costs nothing: a node's sources are its handful of outbound
peers, and the three lowest values rarely share one.

[^ranking]: Firing on a fixed threshold would make the number of
attempts grow with the table. Taking the lowest few gives a fixed number
of attempts per round, and the block hash makes a ranking as hard to aim
at as a threshold. The cost is disagreement: the value is the same on
both sides, but each ranks it against its own table. For tables of
similar size, a pair in one side's lowest three is in the other's lowest
three about 69% of the time, and in the lowest one 50% of the time. The
other attempts hold a socket for two minutes and connect to nothing.

[^window]: A pending `connect()` stays in `SYN_SENT` while the operating
system retransmits the SYN: about two minutes on Linux, with
retransmissions after 1, 2, 4, 8, 16, 32, and 64 seconds, and about 75
seconds on macOS. The first retransmission to arrive after the other
side's mapping exists completes the simultaneous open, so one pending
attempt covers the whole window with no retry schedule of its own, and
the two sides may start up to two minutes apart. R-8.2's retries matter
only when the far side answers with a reset, which a NAT without a
mapping does not.

[^hold]: Whichever node connects the block first sends first. Behind a
NAT the early SYN is dropped and retransmitted; a node with no filtering
at all accepts it before its own round has started. Holding the socket
untouched lets it become the session's connection when the round starts.
Held sockets are cheap and bounded, and a scanner gains nothing from
one, since nothing is ever sent on it.

[^extra-slot]: Using an ordinary outbound slot would let the
announcements a node happens to hold influence which ordinary peers it
has. One extra slot bounds the influence to one connection, and bounds
the network: with `HP_OUTBOUND_MAX` of 1, N participants hold at most N
punched connections.

**Why ECDH and not a hash of the two public keys?** A value anyone can
compute from two public keys and a block hash would tell anyone who
connects to whom and when. The shared secret needs one of the two
private keys, so only the two nodes can compute the pair value. Silent
payments (BIP 352) use the same construction for the same reason.

**Why no signature on announcements?** A signature would stop a third
party from attaching someone else's key to an address. It would not stop
anyone from attaching their own fresh key to any address, which is all a
flood needs, so it would cost 64 bytes per element and buy nothing. The
announced endpoint is a hint; the table bounds how many hints one peer
can plant and the session limits bound what they cost.

**Why a dedicated punch port and not the P2P port?** Reusing the
listening port would need `SO_REUSEPORT` on the existing listener, a way
to tell punched connections from ordinary inbounds on one socket, and
would leave out nodes that do not listen at all. On a dedicated port
every accepted connection is a punched one, and `-listen=0` still works.

**Why nothing is retried or reported.** A failed session says nothing
the node could act on: the other side may not hold the entry, may have
no free slot, may have rejected the network group, or may have ranked
the pair lower against a larger table. All of that resolves itself with
the next announcement and the next block. Retrying would only send more
SYNs to the same address.

**Not taken.** A threshold instead of a ranking; proof of work on
announcements (a flooder needs a handful of elements per victim, while
an honest low-power node would pay on every one); attestation of the
announced address by the relaying peer (a third party again); a pull
message for table entries; keeping announcements in the address manager;
keeping old keys usable after rotation; one key for both address
families (dropped in 0.3.1, see [^key-per-family]); a table keyed by the
announced address.

## Backward compatibility

Nodes that do not implement this document are unaffected: the `feature`
message is ignored per BIP 434, `PUNCHKEY` elements carry an unknown
network ID and are skipped by BIP 155 receivers, and they are only sent
to peers that asked for them. Nodes announcing a protocol version below
70017 are not sent the feature. The fixed source port is visible to
peers only as a non-ephemeral port.

A coordinated variant of TCP hole punching is specified in a separate
draft (`bip-tcp-holepunch.md`). The two are alternatives and use
distinct network IDs and feature identifiers so that both can be tried;
one is expected to remain.

## Security considerations

Anyone can put any endpoint and any key in front of any node, and
nothing in an element can be checked before the attempt. The design
therefore bounds what invented elements can cost and ties every bound to
the one thing an attacker cannot invent: the connection the element
arrived on.

**Invented keys and addresses.** Elements are free to make. Each one
costs the receiver a key parse and one ECDH when stored and one hash per
round, and gives the attacker a place in the table and a chance at a
pick. Both are bounded by connections, not by elements: a peer can plant
at most `SOURCE_CAP` entries and displace only its own (R-6.2); a node
processes at most `PUNCHKEY_PER_HOUR` elements per peer, rejected ones
included (R-5.5); entries planted through one peer take at most one of a
round's picks, however many there are and however low their values
(R-7.4); none can be made to rank well on purpose (R-7.2); and each
costs at most one session's attempts before it is dropped (R-7.6). What
remains is proportional to the attacker's presence among the node's
peers: one hostile peer wastes at most one pick in three, and takes the
hole-punch outbound slot for one window in rounds where its best fake
happens to rank first with the initiator role. Such a peer is already
one of the node's outbound peers, with everything that position gives it
over address, transaction, and block relay.

**Floods through honest peers.** An attacker that is not a peer of the
victim reaches it only by relay, inside an honest peer's stream and in
that peer's source group. The relayer processes at most
`PUNCHKEY_PER_HOUR` elements per connection, so dominating its stream
takes many connections to it, and the attacker does not know which
relayers are the victim's peers. Random eviction means each inserted
element mostly evicts the flood's own entries, an honest newcomer is
always stored, and refreshes evict nothing, so a group cannot be held.
At the ceiling, eviction hits the largest group, which is what a flood
inflates. A hostile relayer can withhold instead; the victim's other
peers bound that.

**Reflection.** The only traffic sent to an unverified address is a
session's attempts: one pending `connect()`, whose SYN the operating
system sends about seven times in two minutes, re-opened at most seven
times and only if the far side answers with resets. An element naming a
third party makes each node that picks it send that burst once and drop
the entry. A new key for the same address is a new entry, but every node
starts at most `GROUP_SESSIONS_PER_HOUR` sessions per hour into one
network group whatever the keys, and endpoints must be routable and not
reserved, local, the node's own, or on a bad port. Network-wide, a
target sees a few SYNs per thousand participants per block; the ceiling
is the per-group limit times the number of participants per hour.

**Starving a node.** A node's genuine entry in another table cannot be
evicted by anyone but that table's peer for it, cannot be reset, since
only a new (endpoint, key) combination gets a new `received_at` and the
node alone announces its key, and cannot be outranked on purpose.
Replaying it refreshes it. Announcing the node's address under other
keys makes separate entries that compete like any other fiction and send
the node a bounded number of SYNs, which it holds and drops.

**Grinding.** The key must be in the victim's table before the victim's
tip reached the parent of the block whose hash enters the pair value,
and `received_at` is the victim's clock. Only a miner withholding two
consecutive blocks could grind (see [^parent]).

**Sybil and eclipse.** The hole-punch outbound is one extra slot, kept
out of anchors and diversity accounting, and its peer must pass outbound
diversity. Taking it needs a real host in a network group the node
lacks, a ranking the attacker cannot influence, and at most one pick per
round per peer the attacker controls.

**Chain dependence.** A node starved of blocks holds no rounds. Delaying
its blocks delays its rounds but cannot choose the pair values without
mining. A node catching up holds rounds nobody else evaluates, bounded
by the session cap. A wrong clock changes nothing, since no clock enters
the protocol.

**Resources.** At most `TABLE_MAX` entries of under a hundred bytes; at
most `MAX_ACTIVE_SESSIONS` pending attempts and `HELD_MAX` held sockets,
which are never read or written and are closed after `HOLD_MS`; one hash
per eligible entry per round.

**Reports.** A peer can report any address. Only two reporting peers in
different network groups make an external address, and a single
dissenter changes nothing (R-2.2). A wrong external address makes the
node announce something unreachable, which wastes others' attempts
within their limits and the node's own picks.

**Privacy.** No announcement names a peer, and nobody but the two nodes
learns which pairs connect: two public keys do not give the shared
secret, and even the two nodes cannot know before the block arrives.
What is public is participation: a home node's clearnet endpoint, under
a key that identifies it for up to a day and is tied to one address
(R-4.3), which is why taking part is opt-in. A node's IPv4 and IPv6
endpoints carry different keys, so the protocol does not link them
(R-4.2). The fixed source port, the feature, and SYNs from the punch
port shortly after each block tell peers and on-path observers that the
node takes part.

## Reference implementation

A reference implementation for Bitcoin Core is planned and will be
linked here. Test vectors are in
[`bip-tcp-holepunch-coordinatorless/`](bip-tcp-holepunch-coordinatorless/):
[`vectors.json`](bip-tcp-holepunch-coordinatorless/vectors.json),
generated by
[`gen_vectors.py`](bip-tcp-holepunch-coordinatorless/gen_vectors.py).

## Test vectors

`vectors.json` holds valid and invalid encodings of the `feature` payload
and of `PUNCHKEY` elements for both families, each with decoded fields
or the expected rejection reason, and pairing vectors: for three fixed
keys and two block hashes, the public keys, the shared secret, the block
hash in both byte orders, the pair value, the role bit, and the
initiator, plus the ranking a node holding two of the entries derives.
Implementations are expected to reproduce every encoding byte for byte,
reject every invalid vector, and reproduce every pair value and role.
The vectors use documentation address ranges; routability and the other
checks in R-2.1, R-5.1, and R-7.3 still apply to real elements.

## Changelog

* 0.3.1 (2026-10-17): one key per address family instead of one per
  node, rotated independently, so that a node's IPv4 and IPv6 endpoints
  are not linked by the protocol.
* 0.3.0 (2026-10-16): rewritten as a standalone document. Drafts 0.1.0
  and 0.2.0, which shared text with the coordinated draft, are in the
  repository history.
