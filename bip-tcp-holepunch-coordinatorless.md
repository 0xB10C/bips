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
  Version: 0.1.0
  Requires: 155, 324, 434
```

## Abstract

This document specifies how two Bitcoin nodes that cannot accept incoming
TCP connections, because each sits behind a NAT with endpoint-independent
mapping or behind a stateful firewall, establish a direct TCP connection
to each other by TCP simultaneous open ("hole punching") without a third
party telling them whom to connect to or when.

A node dedicates one local port per address family, the *punch port*, to
all of its outbound connections. Every peer then reports in its `version`
message the NAT-mapped address and port of that node, so no separate
discovery protocol is needed. The node announces that address together
with a short-lived public key in a new BIP 155 address element that
travels over ordinary address relay, and keeps the announcements it
receives from others in a small table. Every new block starts a *round*:
for each stored announcement the node derives a *pair value* from the
ECDH shared secret of the two keys and the block hash, and sends a SYN
from its punch port to the few announcers with the lowest values. Both
nodes of a pair derive the same value, so they tend to pick each other in
the same round, and the block hash makes the value unknowable until after
both keys were published. Nothing is exchanged before the two SYNs cross.

This document is a coordinator-less alternative to the draft "TCP Hole
Punching for Peer Connections" (`bip-tcp-holepunch.md`), which coordinates
the same simultaneous open through a third node or through a Tor onion
service. Socket handling, discovery of the external address, and the
punch procedure are shared with that draft; the two drafts reserve
distinct network IDs and feature identifiers so that both can be tried
side by side.

## Copyright

This BIP is licensed under the BSD-2-Clause License. Auxiliary code in
`bip-tcp-holepunch-coordinatorless/` is additionally licensed under the
MIT License.

## Motivation

A large share of Bitcoin nodes run on residential connections behind a
NAT and never accept inbound connections. Enabling PCP/NAT-PMP port mapping
by default in Bitcoin Core v30 did not measurably increase the number of
reachable residential nodes[^natpmp]. Such nodes consume inbound slots of
reachable nodes without offering any.

TCP hole punching lets two such nodes connect directly without relaying
traffic through a third party. A survey among developers[^survey] found
that roughly two thirds of residential IPv4 NATs use endpoint-independent
mapping, for which hole punching works, and that IPv6 deployments are
usually "no NAT, stateful firewall", which the same procedure traverses.
Measurements of libp2p's DCUtR protocol report about 70% success for TCP
hole punching at Internet scale[^dcutr-measurement].

Every way of coordinating a simultaneous open considered so far needs
either a third node that both parties stay connected to, or a second
network such as Tor on both sides. A coordinator learns who connects to
whom, can refuse or redirect, and exposes one edge of the peer graph in
every announcement; the Tor variant adds an onion service to every
participating node. This document removes the coordinator. Addresses
travel over address relay, which exists anyway, and the moment to connect
is taken from the arrival of the next block, which every node sees within
seconds of every other[^no-messages].

Hole-punched connections are a best-effort addition. They do not replace
ordinary inbound and outbound connections, port mapping, or privacy
networks. The goal is extra connection slots and more peer diversity for
nodes that currently have none to offer.

## Scope

This specification supports pairs of nodes that both have
endpoint-independent mapping (EIM) in the sense of RFC 4787, including
nodes that have no NAT but a stateful firewall. NATs with address-dependent
or address-and-port-dependent mapping ("symmetric" NATs, common with
carrier-grade NAT and mobile networks) are out of scope: a node that
detects such a NAT does not participate. Filtering behaviour
(endpoint-independent or address-and-port-dependent) does not matter; a
pending connection attempt retransmits its SYN until the other side's
mapping exists.

Participation is opt-in. A node that does not enable it behaves exactly as
before, and nothing in this document changes how ordinary connections are
made or accounted. A node in initial block download or on a stale tip
does not take part in rounds and makes no attempts.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

Integer fields are little-endian unless the name ends in `_be`.
`CompactSize` is the variable-length integer used elsewhere in the P2P
protocol, minimally encoded.

**Endpoint.** A transport address encoded as a BIP 155 address element
without `time` and `services`:

| Type          | Name       | Description |
|---------------|------------|-------------|
| `uint8`       | `net`      | BIP 155 network ID, `IPV4` (1) or `IPV6` (2) |
| `CompactSize` | `addr_len` | 4 for `IPV4`, 16 for `IPV6` |
| `uint8[]`     | `addr`     | address bytes |
| `uint16_be`   | `port`     | port, big-endian as in BIP 155 |

**Punch port.** A local TCP port per address family that a participating
node reserves for this protocol. By default it is chosen at random from
the dynamic port range (49152 to 65535), excluding ports the
implementation treats as bad, when the node starts; implementations make
it configurable. It MUST NOT change while the node runs[^random-port]. It
is independent of whether the node listens for ordinary inbound
connections.

**Punch-port socket.** A TCP socket bound to the punch port with
`SO_REUSEADDR` and `SO_REUSEPORT` set before binding.

**Reported address.** The address and port a peer puts in the `addr_recv`
field of its `version` message: the source of the connection as that peer
sees it[^addr-recv]. Only reports on outbound connections using a
punch-port socket without a proxy count ("reporting peers").

**External address.** A node's address and port as seen from the
Internet, for one address family: the reported address that at least two
currently connected reporting peers in distinct network groups agree on.
It remains valid only while that agreement holds and no second agreeing
set reports a different endpoint (R-2.2, R-2.3).

**Network group.** The grouping an implementation uses for outbound peer
diversity (for example /16 for IPv4, /32 for IPv6, or autonomous systems).

**Source group.** The network group of the peer an element was received
from, taken from the remote address of that peer's TCP connection, never
from a field of the element.

**Key.** A node's short-lived secp256k1 key pair for this protocol: the
secret `p` and the public key `P`, serialized as a 33-byte compressed
point (R-4.1).

**Entry.** A stored announcement: the announced endpoint, the announced
public key, the element's `time`, the local time the node first received
that (endpoint, key) combination (`received_at`), and its source group.

**Pair value.** A 256-bit value derived from the two parties' keys and a
block hash (R-4.5). Both parties compute the same value; nobody else can.

**Round.** The evaluation of all entries that the arrival of one block
triggers (section 7).

**Roles.** Each session has one **initiator** and one **responder**, in
the sense of BIP 324: the initiator sends the first bytes. The role is
derived from the pair value (R-4.7) and never from whether the operating
system delivered the socket via `connect()` or `accept()`.

**Session.** The local state identified by the pair (local punch port,
peer endpoint). Its start time is the start of the round that picked the
entry (R-7.4).

## Specification

### 1. Sockets

- R-1.1 A participating node MUST make every outbound TCP connection to an
  `IPV4` or `IPV6` peer that is not reached through a proxy from a
  punch-port socket of the peer's address family[^bind-all]. If the
  operating system refuses the connection because the 4-tuple is still in
  use (typically `TIME_WAIT` after a recent connection to the same peer),
  the node MAY use an ephemeral port instead; such a connection is not a
  reporting peer.
- R-1.2 A participating node MUST listen on each punch port. Connections
  accepted there are punched connections; the listener MUST NOT be used
  for anything else.
- R-1.3 Punch connect attempts use punch-port sockets, are non-blocking,
  and a superseded attempt MUST be closed.
- R-1.4 IPv4-mapped IPv6 addresses MUST NOT appear in endpoints, reports,
  announcements, or connect targets. Sockets are per address family.
  Punch-port sockets SHOULD be bound to a stable local address; IPv6
  temporary addresses (RFC 8981) make reports disagree and yield no
  external address.

### 2. External address and the EIM check

- R-2.1 A node MUST ignore reports from proxied connections, from
  connections not made from a punch-port socket, reports whose address is
  not globally routable, and reports with port 0.
- R-2.2 A node has an external address for an address family when at least
  two current reporting peers in distinct network groups report the same
  endpoint. Reports from only one network group do not qualify an endpoint.
  A lone dissenting report cannot replace or invalidate an agreeing set.
- R-2.3 If two such agreeing sets report different endpoints for the same
  family, the node's mapping is not endpoint-independent, or it has several
  external addresses. It then has no external address and MUST NOT announce
  for that family until R-2.2 yields a single endpoint again.
- R-2.4 An external address that stops being valid MUST NOT be used in new
  announcements. Sessions already started continue. No new picks are made
  for that family until R-2.2 holds again (R-7.3).
- R-2.5 On test networks such as regtest, where all nodes share one host,
  an implementation MAY waive the requirement that addresses be globally
  routable (R-2.1, R-5.1, R-7.3) and MAY treat each peer as its own
  network group, so that the procedure can be exercised end to end.

### 3. Signalling

- R-3.1 Support is negotiated per connection with a BIP 434 `feature`
  message. The `featureid` is `https://delvingbitcoin.org/t/2497/22` until
  a BIP number is assigned, then `BIP<n>`. The `featuredata` is:

  | Type     | Name      | Description |
  |----------|-----------|-------------|
  | `uint8`  | `version` | the highest protocol version the sender supports; 0 for this document |
  | `uint32` | `flags`   | no bits are defined; senders set 0, receivers ignore bits they do not know |

  Sending the feature means that the sender understands `PUNCHKEY`
  elements (section 5) and wants to receive them. It does not say whether
  the sender announces itself; a reachable node that merely relays sends
  it too. A node MUST NOT send `PUNCHKEY` elements on a connection unless
  both sides sent the feature and the negotiated version (R-3.2) is one it
  supports. Elements that arrive on a connection without the feature are
  processed all the same; they are well-formed `addrv2` elements.
- R-3.2 The negotiated version of a connection is the lower of the two
  `version` values exchanged[^min-version]. A node that supports version N
  MUST also support every lower version this protocol has defined, and
  follows the rules of the negotiated version on that connection. Only
  version 0 is defined by this document.
- R-3.3 Participating nodes MUST advertise `NODE_P2P_V2`.
- R-3.4 A node SHOULD NOT send the feature on a connection it will close
  right after the handshake, such as a feeler or an address-fetch
  connection: nothing is ever relayed on such a connection, and the
  feature would only tell one more node that the sender runs this
  protocol[^no-feeler-feature].
- R-3.5 This document defines no new P2P message. The only new wire
  element is the `PUNCHKEY` address type, and no BIP 324 1-byte message
  type ID is needed.

### 4. Keys and the pair value

- R-4.1 A participating node generates a secp256k1 key pair when it starts:
  a uniformly random secret `p` in `[1, n-1]` and `P = p·G`. The key
  MUST be generated from fresh randomness, MUST NOT be derived from or
  shared with any other key the node holds, and is used for nothing but
  this protocol. `P` is serialized as a 33-byte compressed point (prefix
  `0x02` or `0x03`, then the x coordinate big-endian).
- R-4.2 A node has one current key at a time and uses it for every address
  family it announces[^one-key].
- R-4.3 The key MUST be replaced whenever an external address it was
  announced with changes, so that a new address is never announced under a
  key that was seen with an old one, and at least every `KEY_ROTATE_H`
  (24 h) regardless, at a time that is not aligned across nodes[^rotation].
  After replacement the node computes pair values with the new key only
  and MAY discard the old secret at once. It SHOULD announce the new key
  promptly (R-5.4).
- R-4.4 The **shared secret** of the node and an entry is `x`, the x
  coordinate of `p · P_entry` as a 32-byte big-endian integer, where `p`
  is the node's current secret and `P_entry` the entry's public key. The
  other party computes `p_entry · P` and obtains the same `x`. If the
  product is the point at infinity the entry is unusable and MUST be
  ignored.
- R-4.5 The **pair value** for an entry and a block is

  ```
  pair = TaggedHash("tcp-holepunch/pair", x || block_hash)
  ```

  where `TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` as
  in BIP 340, and `block_hash` is the 32-byte hash of the block's header in
  the byte order in which it appears in the `prev_block` field of the next
  header[^byte-order]. The value is the same on both sides because `x` is.
- R-4.6 Pair values are **ranked** as 256-bit unsigned integers with the
  first byte most significant; a lower value ranks earlier.
- R-4.7 The **role** follows from the pair value: let `bit` be the least
  significant bit of the last byte of `pair`. The party whose compressed
  public key is lexicographically smaller is the initiator if `bit` is 0
  and the responder if `bit` is 1; the other party takes the other
  role[^coin-flip]. Both parties know both keys, so no exchange is needed.

### 5. Announcements: the `PUNCHKEY` address type

This document reserves BIP 155 network ID `0x09`, enumeration
`PUNCHKEY`[^net-id]. The `addr` field is:

| Type        | Name     | Description |
|-------------|----------|-------------|
| `uint8`     | `net`    | `IPV4` (1) or `IPV6` (2) |
| `uint8[]`   | `addr`   | the announcer's external address, 4 or 16 bytes |
| `uint8[33]` | `pubkey` | the announcer's current public key, compressed |

The element's `port` field is the port of the announcer's external
address, `services` the announcer's services (MUST include `NODE_P2P_V2`),
and `time` the announcement time. Valid `addr` lengths are 38 and 50
bytes.

- R-5.1 Receivers MUST reject elements with an invalid length, a `net`
  outside the set above, an `addr` that is not globally routable, a `port`
  of 0, a `pubkey` that is not a valid compressed point (prefix other than
  `0x02` or `0x03`, x coordinate not below the field size, or x not on the
  curve), `services` without `NODE_P2P_V2`, or a `time` outside
  `now - ENTRY_TTL < time <= now + FUTURE_SKEW` (2 h and 10 min). A
  rejected element is ignored; rejection alone is not a reason to
  disconnect the sender.
- R-5.2 **No storage.** `PUNCHKEY` elements MUST NOT be added to the
  address manager, persisted, or returned in response to `getaddr` other
  than under R-5.7. Accepted elements go to the announcement table of
  section 6.
- R-5.3 **Relay.** An element MAY be relayed to at most `RELAY_FANOUT` (2)
  peers that sent the feature and `sendaddrv2`, only if
  `now - RELAY_TTL < time <= now + FUTURE_SKEW` (10 min each), never back
  to the peer it came from, and using the implementation's ordinary
  address relay timing. Relays MUST preserve `time`; receiving or relaying
  an element MUST NOT restart its expiry. Elements with an older `time`
  are stored if R-5.1 passes but not relayed. Elements MUST NOT be sent to
  peers that did not negotiate `sendaddrv2`. Announcers send their element
  alone or in an `addrv2` message of at most ten elements, since
  implementations commonly relay only small messages.
- R-5.4 **Self-announcement.** A node announces, per address family, only
  while it has a valid external address (R-2.2) whose port is not one it
  would itself treat as a bad port (R-7.3), and at least one free
  hole-punch outbound slot (section 9) or one free inbound slot, counting
  slots reserved by sessions (R-7.4) as used[^both-announce]. The element
  carries the current key and `time = now`. It is sent to every peer that
  sent the feature (R-3.1), at most once per `ANNOUNCE_INTERVAL` (30 min)
  per peer, and once more promptly after the key or the external address
  changed. A node announces one element per address family at a time.
- R-5.5 Elements count against the receiving peer's address rate limit as
  one address each.
- R-5.6 A node MUST ignore elements that carry its own public key or one of
  its own external addresses.
- R-5.7 **Synchronisation (OPTIONAL).** In its response to a `getaddr`
  from a peer that sent the feature and `sendaddrv2`, a node MAY include up
  to `SYNC_MAX` (64) unexpired entries of its table, chosen uniformly at
  random, in addition to the ordinary addresses and within the response's
  size limit[^sync]. It MUST NOT include them in responses to other peers.
  The requester processes them as elements received from the responding
  peer, so their source group is the responder's.

### 6. The announcement table

The table bounds how many announcements a node keeps and, more
importantly, how much of it any one peer can fill. Placement follows the
address manager's new table[^source-bucket]. The source group chooses a
small allotment of buckets, the element chooses the slot inside it, and a
local secret makes both unpredictable.

- R-6.1 Each node holds a 32-byte secret `key`, generated at startup from
  fresh randomness and never shared, used only for table placement.
- R-6.2 Entries are identified by (endpoint, `pubkey`). Receiving an
  element whose (endpoint, `pubkey`) is already stored refreshes that
  entry's `time` to the larger of the two values and leaves `received_at`
  and its slot unchanged. An element with a different `pubkey` for a
  stored endpoint, or a different endpoint for a stored `pubkey`, is a
  distinct entry.
- R-6.3 The table has `TABLE_BUCKETS` (64) buckets of `BUCKET_SIZE` (16)
  slots. With `src` the source group, `grp` the network group of the
  announced address, both in the implementation's byte representation,
  `endpoint` encoded as in Terminology, hashes read as little-endian
  integers before the modulo, and `allot` and `bucket` serialized as
  `uint32` when hashed, the RECOMMENDED placement is:

  ```
  allot  = SHA256(key || 0x00 || src || grp)                  mod BUCKETS_PER_SOURCE
  bucket = SHA256(key || 0x01 || src || allot)                mod TABLE_BUCKETS
  slot   = SHA256(key || 0x02 || bucket || endpoint || pubkey) mod BUCKET_SIZE
  ```

  Elements from one source group can therefore occupy at most
  `BUCKETS_PER_SOURCE` (8) buckets, `BUCKETS_PER_SOURCE * BUCKET_SIZE`
  (128) slots, and the same element from the same source always maps to
  the same slot. An implementation MAY use a different placement with the
  same properties: keyed by a local secret, buckets chosen by the source
  group with at most `BUCKETS_PER_SOURCE` buckets per source group, and
  the slot chosen by the entry.
- R-6.4 If the slot holds a different entry, the newcomer replaces it only
  if that entry has expired (R-6.5); otherwise the newcomer is
  dropped[^occupant].
- R-6.5 An entry expires when `now >= time + ENTRY_TTL`. Expired entries
  MUST NOT take part in rounds and MAY be removed at any time.
- R-6.6 An entry is removed when a round picks it (R-7.6).
- R-6.7 The table is not persisted. A restart starts with an empty table.

### 7. Rounds

- R-7.1 **Trigger.** A round starts when the node's active chain tip
  changes to a block `B`, provided the node is not in initial block
  download and it first received `B`'s header less than `ROUND_FRESH_MS`
  (120000 ms) ago[^block-trigger]. Each block hash triggers at most one
  round. The round's start time is the time of the tip change.
- R-7.2 **Eligibility.** An entry takes part in the round for `B` only if
  its `received_at` is earlier than the time the node first received the
  header of `B`'s parent[^parent-rule]. A header the node received before
  its current run counts as received before every entry. Implementations
  therefore record, for each header accepted in the current run, when it
  was first received by any message.
- R-7.3 **Candidate checks.** An eligible entry is a candidate if all of
  the following hold:
  - it has not expired, and the node has a punch port and an external
    address for the entry's address family;
  - the endpoint is globally routable, is not one of the node's own
    addresses or external addresses, and its port is not one the
    implementation treats as a bad port for outbound connections;
  - the node has no connection and no session to the endpoint, and no
    session with an entry carrying the same `pubkey`;
  - no session to the same address started within `PER_IP_INTERVAL`
    (10 min), and fewer than `GROUP_SESSIONS_PER_HOUR` (4) sessions to
    addresses in the endpoint's network group started in the last hour;
  - with the role from R-4.7 for this round: as initiator, the hole-punch
    outbound slot is free and the endpoint passes the node's outbound
    network-group diversity rules against its existing outbound peers; as
    responder, an inbound slot is free. Reserved slots count as used.

  The address, port, and network group checked here are the announced
  ones. They cannot be verified before the attempt, and they need not be:
  the node sends its SYN to exactly the endpoint it evaluated, so a false
  announcement costs one session's attempts and nothing else[^self-verify].
- R-7.4 **Picks.** The node computes the pair value (R-4.5) of every
  candidate for `B`, sorts the candidates by it (R-4.6), and walks the
  list from the lowest value. It takes a candidate unless the candidate's
  network group equals that of a candidate already taken in this round or
  the slot its role needs has been reserved meanwhile. It stops after
  `PICKS_PER_ROUND` (3) picks, or earlier when another session would
  exceed `MAX_ACTIVE_SESSIONS` (6)[^ranking]. For each pick the node
  reserves the slot its role needs until the session ends and starts a
  session (section 8) with the entry's endpoint and the round's start as
  the session start. A node with neither a free hole-punch outbound slot
  nor a free inbound slot skips the round.
- R-7.5 No attempt is made outside a round, and no entry is attempted more
  than once per announcement.
- R-7.6 A picked entry is removed from the table whatever the outcome. It
  comes back only with a new announcement, which then waits for R-7.2
  again.

### 8. Punch procedure

#### Attempts

- R-8.1 On a pick, the node immediately opens a punch-port socket and
  calls `connect()` on the entry's endpoint, with a deadline at the end of
  the window (`WINDOW_MS`, 120000 ms after session start). The attempt is
  left pending: the operating system retransmits the SYN on its own, and
  the pending attempt keeps the NAT mapping towards the peer
  alive[^window]. At the deadline the node MUST close any pending attempt
  and MUST NOT start further attempts. It continues to accept matching
  sockets from the punch-port listener until the session deadline in
  R-8.8.
- R-8.2 If an attempt fails before the deadline (connection refused or
  reset, unreachable, given up by the operating system, or any other
  error), the node MUST close the socket, wait `RETRY_MS` (1000 ms),
  doubled after each failure, and open a new attempt, until the deadline.
  The node MUST NOT run more than one attempt at a time per session; with
  these numbers a session makes at most seven attempts.
- R-8.3 An attempt that fails because the 4-tuple is already in use MUST
  be closed and MUST NOT be retried. This error alone does not establish
  the session. The node waits for a matching socket from the punch-port
  listener (R-8.4) until the session deadline in R-8.8.

#### Establishment

- R-8.4 The session's connection is the first socket whose remote endpoint
  equals the entry's endpoint exactly, obtained either by a completed
  `connect()` of this session or by `accept()` on the punch-port listener.
  Because both parties use fixed ports, at most one TCP connection can
  exist per session. A socket accepted on the punch-port listener that
  matches no session is *held*: nothing is read from or written to it, and
  it becomes the session's connection if a session for its remote endpoint
  starts within `HOLD_MS` (10000 ms), otherwise it is closed then. A node
  holds at most `HELD_MAX` (8) sockets and closes the oldest to make
  room[^hold].
- R-8.5 On establishment the node stops the attempts. The initiator
  immediately sends its BIP 324 initiator bytes. The responder sends
  nothing until BIP 324 bytes arrive. If the responder's connection is
  closed by the peer before any byte arrived, the peer was not expecting it
  yet: the session does not end, and the responder resumes attempts under
  R-8.1 and R-8.2 and keeps accepting a matching socket, until the deadline
  of R-8.8. A connection closed after bytes were exchanged ends the session
  as a failure.
- R-8.6 The punched connection MUST use the BIP 324 v2 transport. A v1
  prefix on the connection is an error; the connection MUST be closed and
  no v1 fallback attempted.
- R-8.7 The ordinary `version`/`verack` handshake follows on the encrypted
  connection; the initiator sends `version` first. The session is complete
  when the node has received `verack`.

#### Termination

- R-8.8 A session ends when its connection has completed `verack`
  (success) or at the absolute deadline `WINDOW_MS + GRACE_MS`
  (125000 ms after session start) without that (failure). Handshake
  progress MUST NOT extend this deadline. On failure every socket of the
  session MUST be closed and the reserved slot released.
- R-8.9 No outcome is reported over the protocol, and nothing is retried
  within the same announcement (R-7.5). The other party either sees a new
  connection or does not.

#### Timing and mapping liveness

- R-8.10 Both parties start their sessions when their own tip changes to
  `B`. The start times differ by the difference in block propagation and
  validation between the two nodes, normally seconds and rarely more than
  a minute. The pending attempts on both sides mean that the two SYNs need
  to cross only once, anywhere in the overlap of the two windows; the
  first SYN to arrive before the other side's mapping exists is dropped
  and retransmitted. No clock synchronisation is involved[^block-trigger].
- R-8.11 R-1.1 makes any node with outbound peers keep its mapping alive
  regardless of sessions, and a pending attempt refreshes it towards the
  peer. No connection has to be retained for this protocol.

### 9. Classification and slots

- R-9.1 The initiator accounts the punched connection as a **hole-punch
  outbound**, one slot in addition to its ordinary automatic outbound slots
  (`HP_OUTBOUND_MAX` = 1). A node MUST NOT use it as an anchor and MUST NOT
  count it when deciding whether its outbound connectivity is diverse enough
  to record address manager failures[^extra-slot]. The responder accounts
  the connection as inbound. The initiator is the party that acts as
  BIP 324 initiator and sends `version` first, exactly as for any outbound
  connection.

### 10. Invariants

| ID | Invariant | Test shape |
|----|-----------|------------|
| I-1 | Each session has exactly one initiator, determined by the pair value (R-4.7). The initiator sends the first bytes (BIP 324 key, then `version`); the responder sends nothing before receiving BIP 324 bytes. | Two nodes with known keys and a chosen block; capture first bytes on the wire; swap the block for one with the other role bit. |
| I-2 | A session is keyed by (punch port, peer endpoint) and has at most one connection, whose remote endpoint equals the entry's endpoint exactly. A socket accepted on the punch port that matches no session is held for at most `HOLD_MS`, untouched, and closed unless a session for its endpoint starts meanwhile; at most `HELD_MAX` are held. | Connect to the punch port from an unexpected endpoint; assert nothing is sent and the socket closes after `HOLD_MS`. Connect, then start a session for that endpoint; assert it uses the held socket. |
| I-3 | Every non-proxied clearnet outbound connection, every punch attempt, and the listener of one family share the punch port, except connections that fell back to an ephemeral port per R-1.1, which never report. | Inspect local ports of all sockets. |
| I-4 | Connect attempts go only to endpoints of entries picked in a round: routable, not local, not the node's own address, same family, not a bad port; one attempt at a time per session; at most seven attempts per session. | Feed elements with invalid endpoints; count SYNs with a socket mock. |
| I-5 | At most `PICKS_PER_ROUND` sessions start per round, at most `MAX_ACTIVE_SESSIONS` exist, at most one per remote address per `PER_IP_INTERVAL` and `GROUP_SESSIONS_PER_HOUR` per network group. | Fill the table; connect blocks; count sessions. |
| I-6 | Every session ends within `WINDOW_MS + GRACE_MS` in success or failure and releases every socket except the session connection and the reserved slot. | Drive sessions to both outcomes; compare socket counts. |
| I-7 | `PUNCHKEY` elements never enter the address manager or persisted files, are not relayed outside `RELAY_TTL`, leave the node only towards peers that sent the feature and `sendaddrv2`, and a `getaddr` response carries at most `SYNC_MAX` of them. | Send elements; query the address manager and `getaddr` from peers with and without the feature; restart. |
| I-8 | A hole-punch outbound exists only as the initiator side of a session whose peer endpoint is that of a picked entry and passes outbound diversity; at most `HP_OUTBOUND_MAX` at a time; never an anchor. | Entry in an existing outbound's network group: assert no initiator session. |
| I-9 | Punched connections use BIP 324 without v1 fallback; both parties advertise `NODE_P2P_V2`. | Send v1 `version` on a punched connection; assert close. |
| I-10 | A node has an external address only while two reporting peers in distinct network groups agree on its endpoint and no second agreeing set disagrees (R-2.2, R-2.3); it announces only with an external address, its current key, and a free slot of either kind; a pick reserves the slot its role needs. | One dissenting report: external address kept. Two agreeing dissenting reports: external address dropped, no announcement. Both slots taken: no announcement, no picks. |
| I-11 | Table placement is keyed by a local secret; entries from one source group occupy at most `BUCKETS_PER_SOURCE * BUCKET_SIZE` slots; a live entry is not displaced before it expires; a re-received entry keeps its `received_at`; a picked entry is removed. | Flood from one peer with distinct addresses and keys; count stored entries. Re-send a stored element; assert eligibility unchanged. |
| I-12 | The key is replaced whenever an announced external address changes and at least every `KEY_ROTATE_H`; a new address is never announced under a key seen with an old one; pair values use the current key only. | Change the reported address; assert a new key is announced and the old one never with the new address. |
| I-13 | An entry takes part only in rounds for blocks whose parent's header the node first received after the entry; the pair value depends on that block's hash. | Insert an entry, connect one block: no attempt. Connect another: attempt. Replace the block hash: different pick. |

### 11. Limits

| Name | Default | Used in |
|------|---------|---------|
| punch port | random in 49152 to 65535, fixed per run | Terminology |
| `WINDOW_MS` | 120000 | R-8.1 |
| `RETRY_MS` | 1000, doubled after each failure | R-8.2 |
| `GRACE_MS` | 5000 | R-8.8 |
| `HOLD_MS` / `HELD_MAX` | 10000 / 8 | R-8.4 |
| `PICKS_PER_ROUND` | 3 | R-7.4 |
| `MAX_ACTIVE_SESSIONS` | 6 | R-7.4 |
| `PER_IP_INTERVAL` | 10 min | R-7.3 |
| `GROUP_SESSIONS_PER_HOUR` | 4 | R-7.3 |
| `ROUND_FRESH_MS` | 120000 | R-7.1 |
| `TABLE_BUCKETS` / `BUCKET_SIZE` / `BUCKETS_PER_SOURCE` | 64 / 16 / 8 | R-6.3 |
| `ENTRY_TTL` | 2 h | R-5.1, R-6.5 |
| `RELAY_TTL` / `FUTURE_SKEW` | 10 min / 10 min | R-5.1, R-5.3 |
| `RELAY_FANOUT` | 2 | R-5.3 |
| `ANNOUNCE_INTERVAL` | 30 min | R-5.4 |
| `SYNC_MAX` | 64 | R-5.7 |
| `KEY_ROTATE_H` | 24 h, maximum key lifetime | R-4.3 |
| `HP_OUTBOUND_MAX` | 1 | R-9.1 |

## Rationale

[^natpmp]: Observations on bnoc.xyz comparing reachable residential nodes
before and after Bitcoin Core v30 enabled `-natpmp` by default showed no
clear increase.

[^survey]: Results posted in the Delving thread using the tcp-nat-check
tool: 11 of 17 IPv4 environments were EIM, the rest address-and-port
dependent (carrier-grade NAT, campus networks, some VPNs, Docker on
macOS); IPv6, where present, had no NAT.

[^dcutr-measurement]: Trautwein et al., "Large-Scale Measurement of NAT
Traversal for the Decentralized Web", 6.25 million DCUtR attempts, about
70% success for both TCP and QUIC. DCUtR synchronises the two sides over
an existing relay connection to within a round-trip time; this document
accepts start times up to two minutes apart instead and holds the SYN.

[^no-messages]: The coordinated draft needs two messages because a
coordinator has to tell each party the other's endpoint and who speaks
first. Here both parties already hold each other's announcement, and the
role follows from the pair value, so there is nothing left to say before
the SYNs cross. The price is that both sides must announce, and that a
node cannot ask for a particular peer; see [^both-announce] and the
security considerations.

[^addr-recv]: The `version` message's `addr_recv` field has always carried
the address the sender observed for the receiver; this BIP only makes the
port meaningful by fixing the source port of outbound connections. Any
peer, upgraded or not, serves as a reporting peer.

[^bind-all]: Binding every outbound connection to the punch port makes every
peer a reporting peer, keeps the NAT mapping alive as long as the node has any
outbound connection, and removes any need for dedicated probe connections. A
peer learns that the node uses a fixed source port, which reveals nothing
beyond the node's address that it already sees. Two connections to the same
remote endpoint from one punch port are impossible: R-1.1's fallback covers
reconnecting to a peer whose 4-tuple is still in `TIME_WAIT`. The listener
and the connecting sockets coexist on one port with `SO_REUSEPORT` on
Linux, the BSDs, and macOS; Windows has no equivalent and is not covered by
this draft.

[^random-port]: No participant needs to know the punch port: peers see
only the NAT-mapped port, which the node learns from their reports, and
announcements carry that external port. What matters is that the port does
not change, since every reporting peer, the NAT mapping they keep alive, and
the punch attempts must share one mapping; a new port would need two fresh
reporters before the node could announce again. A random port is preferred
over a well-known one for two reasons. A port-preserving NAT exposes the
local port as the external port, so a fixed number would mark the node's
connections as hole punching traffic to any firewall or passive observer,
which BIP 324 cannot hide; a random high port looks like any client. And two
nodes behind one NAT would otherwise ask for the same port and force the
NAT to remap one of them.

[^min-version]: Agreeing on the lower of the two versions lets an upgrade
spread gradually; the cost is that a node has to keep the old rules
around. This choice cannot be revised once deployed, since old nodes will
interpret the field the way it was defined when they shipped.

[^no-feeler-feature]: Feelers and address-fetch connections go to addresses
chosen at random from the address manager and close after the handshake.
Sending the feature on them would spread the fact that the node runs this
protocol to many more nodes than it ever relays to, for no benefit.

[^one-key]: One key per node rather than one per family keeps the pair
value, and hence the role, the same for a pair whichever family they end
up using, and halves the number of keys an observer can collect. A node
with both families announces two elements with the same key; R-7.3
prevents two sessions with the same key at once.

[^rotation]: Announcements are relayed network-wide and bind a public key
to a clearnet address, so anyone running a node can collect them. Home
addresses change: many ISPs reassign them daily or on reconnect. A key that
outlives an address change is a persistent name for a node that today has
none, since unreachable nodes are in nobody's address manager, and it would
let an observer follow the node from one ISP-assigned address to the next.
Rotating on a schedule alone does not prevent that: if the key lasts a day
and the address changes about daily, each key overlaps two addresses, the
first links address one to address two, the next links two to three, and
the node can be followed indefinitely. Hence the rule that a new external
address is never announced under an old key, which breaks the chain, with
the daily maximum as a bound for a node whose address is stable, and an
unaligned time so that many nodes do not rotate in the same minute. A key
costs nothing to replace, unlike an onion service, but rotating more often
would hurt: every new key is a new entry in every table (R-6.2) that waits
for a block before it can be picked (R-7.2), while picks of the old key by
others go unanswered. Within one run, a port-preserving NAT keeps the same
external port across an address change; that port is a weak identifier
that a restart resets.

[^byte-order]: This is the order in which a block hash is serialized in
every P2P message and the order in which `SHA256d` produces it; the
hexadecimal form shown by block explorers and RPCs is the reverse. The test
vectors give both.

[^coin-flip]: Deriving the role from the pair value gives each pair a fresh
coin flip per round. A fixed rule, such as the smaller key always
initiating, would tie every pair to one combination of slots: the
initiator needs its single hole-punch outbound slot and the responder an
inbound slot, so a node whose outbound slot is taken could never connect
to half of its candidates. With the flip, a pair connects whenever either
combination is free on both sides.

[^net-id]: The coordinated draft reserves `0x08` with a different layout.
Distinct IDs keep the two experiments from misreading each other's
elements; whichever draft proceeds keeps its ID.

[^both-announce]: Without a coordinator there is nobody to ask for an
introduction, so a node that only wants outbound connections still has to
be in the other side's table, which means announcing. A node with no free
slot of either kind has nothing to offer and nothing to gain; it stops
announcing and its entries age out of every table.

[^sync]: Gossip reaches a node only along relay paths of upgraded peers, so
early on most tables are nearly empty and two nodes rarely hold each
other. Letting a node pull a sample of a peer's table with the `getaddr`
it sends anyway on new outbound connections fills tables within a few
connections. The responding peer is the source for placement, so the
sample cannot escape its allotment, and every pulled entry still waits for
a block before it can be picked. Serving them only to peers that sent the
feature keeps them out of ordinary address caches.

[^source-bucket]: The announced address is whatever the announcer wrote,
so bucketing by it would let one peer claim a thousand network groups for
free. The peer an element arrives from is real: its network group comes
from the TCP connection. Placing by the source bounds what one peer can
fill to its allotment, however many addresses it invents, and filling more
of the table means being more of the node's peers from more network
groups. The claimed network group only picks a bucket within the
allotment, as in the address manager's new table. Admission therefore
cannot guarantee that the stored addresses are diverse, since their groups
may be fiction; diversity is checked at pick time instead (R-7.3), where a
lie costs one wasted SYN and nothing more.

[^occupant]: Letting a newcomer displace a live entry would let a flood
through one peer churn that peer's allotment continuously, and since every
displaced and reinserted entry waits for a block again (R-7.2), a churned
allotment never yields a pick. Keeping the occupant means a slot is held
for at most `ENTRY_TTL`, and a flood merely fails to insert, which is also
how the address manager treats collisions with entries that are not stale.

[^block-trigger]: A block is the one event every node observes within
seconds of every other, with no clock involved. Header timestamps were
considered as the trigger instead: they are set by miners, may be off by up
to two hours, and every node would still have to decide when "the time in
the header" has arrived, which brings clocks back. Rounds at fixed
wall-clock intervals need clocks to agree within the window; most do, but
a node with a wrong clock would punch alone forever without noticing.
Using the arrival of the block costs variance in the start times, which
the window absorbs, and the freshness bound stops a node that is catching
up from holding one round per block it connects.

[^parent-rule]: The pair value is unpredictable only if the block did not
exist when the key was chosen. Requiring the block to arrive after the
entry is not enough: whoever sees a block a second before the victim does,
which is ordinary propagation variance, can grind keys against the known
hash for that second, deliver the announcement, and still arrive first. A
commodity machine tries roughly 300 000 keys per second, about a billion
per hour, enough to land in the lowest three of a thousand with near
certainty. Requiring the entry to predate the arrival of the block's
*parent* puts a whole block interval, ten minutes on average and never
less than the propagation delay, between the latest possible key choice
and the earliest knowledge of the hash. Only a miner who finds two blocks
in a row and withholds both could grind, at a cost that dwarfs the prize.
`received_at` is the node's own clock, so an announcer cannot backdate it.
The same ordering, a public random value fixed only after the keys it is
combined with, is how Tor keeps onion-service directory positions from
being chosen by an attacker[^beacon-precedent].

[^beacon-precedent]: Tor proposal 250 and the shared random value
specification: hidden service directory positions derive from the
directory's identity key and a daily value produced jointly by the
directory authorities, because positions derived from the key alone were
predictable far ahead and let an attacker choose keys that land on a
target.

[^self-verify]: The node evaluates the announced endpoint and then sends
its SYN to exactly that endpoint. Nobody can steer it into a network group
it rejected, and an invented address receives at most one session's
attempts from this node per announcement before the entry is dropped
(R-7.6).

[^ranking]: An earlier design fired when the pair value was below a fixed
threshold. A threshold makes the attempt rate grow with the table, so a
node would have to tune it to its table size. Taking the lowest few gives
a fixed number of attempts per round whatever the table holds, and the
block hash makes a ranking as hard to aim at as a threshold. Its cost is
disagreement: the pair value is the same number on both sides, but each
side ranks it against its own table. For tables of similar size with
independent other entries, a pair that ranks in one side's lowest three
ranks in the other's lowest three with probability 2.0625/3, about 69%
(the integral of e^(-2λ)(1+λ+λ²/2)² over λ ≥ 0, divided by 3); for the
lowest one alone it is 50%. The remaining attempts hold a socket for two
minutes and connect to nothing. Three per round means a node with a free
slot of each kind gets about two mutual picks per round, which fills its
hole-punch outbound slot within a few blocks.

[^window]: A pending `connect()` sits in `SYN_SENT` while the operating
system retransmits the SYN: about two minutes on Linux with its default of
six retransmissions after 1, 2, 4, 8, 16, 32, and 64 seconds, about 75
seconds on macOS. Each retransmission reaches the other side's NAT, and
the first one to arrive after the other side's mapping exists completes
the simultaneous open. One pending attempt thus covers the whole window
without an application retry ladder, and the two sides may start up to two
minutes apart. The coordinated draft uses a 15-second window because a
coordinator starts both sides within milliseconds; here the start times
depend on when each node connects the block. R-8.2's retries matter only
when the far side answers with a reset, which a NAT without a mapping does
not do, or when the operating system gives up before the window ends.

[^hold]: Both parties dial each other, and whichever node connects the
block first sends first. Behind a NAT or stateful firewall the early SYN
never reaches the other node, since no mapping exists yet, and is simply
retransmitted. A node without any filtering, however, accepts it before its
own round has started. Holding the socket, untouched, lets it become the
session's connection when the round starts; the responder's rule to resume
after a zero-byte close covers the other side holding it for less, or not
at all. Held sockets are cheap and bounded, and a scanner gains nothing
from them, since nothing is ever sent on one.

[^extra-slot]: Using one of the ordinary automatic outbound slots would let
the announcements a node happens to hold influence the selection of
ordinary peers; a dedicated extra slot bounds the influence to one
connection. It also bounds the steady state: with `HP_OUTBOUND_MAX` of 1, a
network of N participants holds at most N punched connections, one
outbound and on average one inbound per node.

**Why a dedicated punch port?** Reusing the P2P listening port would
require `SO_REUSEPORT` on the existing listener, a rule for telling
punched connections from ordinary inbounds on the same socket, and would
exclude nodes that do not listen at all. A dedicated port makes every
accepted connection on it a punched one and works with `-listen=0`.

**Why exact endpoint matching and no session identifiers?** Both parties
use fixed ports, so a session corresponds to exactly one TCP 4-tuple;
the kernel delivers that connection either through `connect()` or through
`accept()`, never both. Nothing else connects from the peer's punch port to
ours, so the 4-tuple identifies the session and no in-band confirmation is
needed. This is what restricting the scope to EIM buys.

**Why no v1 fallback on punched connections?** On a simultaneous open both
TCP stacks consider themselves the connecting side, so nothing in the
transport says who speaks first. BIP 324 makes the role explicit and
encrypts the link.

**Why ECDH and not a hash of the two public keys?** Anyone who collects
announcements could compute a value from two public keys and a block hash
and learn which pairs fire and when. The shared secret needs one of the
two secrets, so only the two parties can compute the pair value. Silent
payments (BIP 352) rely on the same construction for the same reason:
a value derived from two published keys that only the two key holders can
derive.

**Why no signature on announcements?** A signature by the announced key
over the endpoint would stop a third party from attaching someone else's
key to an address. It would not stop anyone from attaching their own fresh
key to any address, which is all a flood needs, so it would cost 64 bytes
per element and buy nothing. The announced endpoint is a hint; the table
bounds how many hints one peer can plant and the attempt limits bound what
they cost.

**Why keep announcements out of the address manager?** They are short-lived,
tied to a key, and useless to nodes that do not run this protocol. The
address manager is persistent and feeds ordinary outbound selection, which
this protocol must not influence (R-9.1).

**Why is nothing retried or reported?** A failed session says nothing the
node could act on: the other side may not hold the entry, may have had no
free slot, may have rejected the network group, or may have ranked the
pair lower against a larger table. Any of these resolves itself with the
next announcement and the next block. Retrying within the same announcement
would only send more SYNs to the same address, which is what the attempt
limits exist to prevent.

**Alternatives considered and deferred.** Coordination through a third
node or an onion service (the coordinated draft); rounds at fixed
wall-clock intervals (clocks, see [^block-trigger]); a threshold on the pair
value instead of a ranking (see [^ranking]); proof of work on announcements
(the asymmetry runs the wrong way: a flooder needs a handful of elements
per victim and the per-source bound already limits them, while an honest
low-power node would pay on every announcement); attestation of the
announced address by the relaying peer (a third party with a role in the
protocol again); birthday-paradox port probing for symmetric NATs (out of
scope by design); a sealed reply channel over a relay (an opaque,
unauthenticated flood channel); keeping old keys usable after rotation
(see [^rotation]); one key per address family (see [^one-key]); a request
message to pull table entries (replaced by R-5.7 on `getaddr`); a signature
on announcements (above); a cache of a few dozen announcements without
source bucketing (which any one peer could fill).

## Backward compatibility

Nodes that do not implement this BIP are unaffected: the `feature` message
is ignored per BIP 434, `PUNCHKEY` elements have an unknown network ID and
are skipped by BIP 155 receivers, and they are only sent to peers that
negotiated the feature anyway. Nodes announcing a protocol version below
70017 are not sent the feature.

Binding outbound connections to a fixed source port is a local change
visible to peers only as a non-ephemeral source port.

This document and the coordinated draft are alternatives, not layers. A
node MAY implement both during the experiment: they share the punch port,
the external address, and the punch procedure, and differ only in how a
session starts. Distinct network IDs and feature identifiers keep them
apart on the wire. The intention is to retain one of the two once
experience shows which coordination works in practice.

## Security considerations

**Reflection.** The only traffic sent to an unverified address is the
connect attempts of a session: one pending `connect()` at a time, whose
SYN the operating system sends about seven times over two minutes,
re-opened at most seven times per session and only if the far side
answers with resets; at most three sessions per round, six concurrent,
one per address per ten minutes, four per network group per hour. An
invented address is attempted once per announcement and then dropped.
Across the network, an announcement that reaches every participant's
table is attempted by each of them with probability of about
`PICKS_PER_ROUND` over its table size per round, so a target receives on
the order of a few SYNs per thousand participants per block.

**Grinding.** Pair values cannot be aimed at: the key must be in the
victim's table before the victim sees the parent of the block whose hash
enters the value (R-7.2), and `received_at` is the victim's own clock.
Only a miner withholding two consecutive blocks could grind; see
[^parent-rule]. The table secret (R-6.1) likewise makes placement
unpredictable.

**Sybil and eclipse through the extra slot.** The initiator's hole-punch
outbound is one extra slot, excluded from anchors and diversity accounting
(R-9.1), and its peer must pass outbound diversity (R-7.3). An attacker's
chance of taking that slot in a round equals its share of the node's
candidates, which the table bounds per source group: controlling one of
the node's address-relaying peers yields at most 128 of 1024 slots. Every
announced endpoint must then complete a BIP 324 handshake from the
announced address, so the attacker needs real hosts in network groups the
node does not already have. Nothing is grindable, so repeated
announcements buy nothing beyond those slots.

**Table flooding.** One peer can fill at most its allotment, however many
addresses or keys it invents (R-6.3). A remote attacker flooding through
honest peers lands in those peers' allotments at the ordinary address
relay rate, cannot displace live entries (R-6.4), and gains picks only in
proportion to the slots it holds. Each entry it plants costs the node at
most one session's attempts per announcement.

**Denial of pairing.** Replaying a node's genuine element only refreshes
it (R-6.2). Announcing a node's address with a different key creates
separate entries and does not touch the genuine one; attempts to that
address from such entries are bounded as under reflection. An attacker
cannot keep a victim's entry perpetually ineligible, since only a new
(endpoint, key) combination gets a new `received_at`, and the victim alone
announces its own key.

**Chain dependence.** A node that is eclipsed or starved of blocks holds
no rounds and makes no attempts. An attacker who can delay a node's blocks
can delay its rounds but cannot choose the pair values without mining. A
node on a stale tip holds rounds for blocks nobody else evaluates, and its
attempts go unanswered. A node with a wrong clock is unaffected, since no
clock enters the protocol.

**Lying peers.** A peer can report any address in `addr_recv`. Only
agreement between two reporting peers in distinct network groups produces
an external address, and a single dissenting report changes nothing
(R-2.2). A wrong external address makes the node announce an endpoint
nobody can reach, which wastes other nodes' attempts within their limits
and costs the node its own picks.

**Topology.** No announcement names a peer of the announcer, and no node
learns which pairs connect other than the two parties. A passive observer
sees that a node announces and, on the node's own path, which addresses it
sends SYNs to after a block, which is the same visibility any connection
has.

**Linkability and fingerprinting.** Announcements make a previously
invisible home node's clearnet endpoint and its participation known to
the whole network, under a key that identifies it for up to a day and is
tied to one address (R-4.3), which is why participation is opt-in. The
fixed source port on every outbound connection and the feature tell every
peer, and any passive observer on the path, that the node runs this
protocol, and SYNs from the punch port shortly after each block mark the
attempts. Pairings themselves are hidden: two public keys do not yield the
shared secret, so nobody can tell which nodes connect or when, and the two
nodes themselves cannot before the block arrives.

## Reference implementation

A reference implementation for Bitcoin Core is planned on a branch of the
authors' repository and will be linked here. The punch port, the external
address tracking, and the simultaneous open are shared with the
implementation of the coordinated draft. Test vectors and state tables are
in [`bip-tcp-holepunch-coordinatorless/`](bip-tcp-holepunch-coordinatorless/):
[`vectors.json`](bip-tcp-holepunch-coordinatorless/vectors.json) generated
by [`gen_vectors.py`](bip-tcp-holepunch-coordinatorless/gen_vectors.py),
and [`state-machines.md`](bip-tcp-holepunch-coordinatorless/state-machines.md).

## Test vectors

`vectors.json` contains valid encodings with decoded fields and invalid
encodings with the expected rejection reason for the `feature` payload and
for `PUNCHKEY` address elements of both families, and pairing vectors: for
three fixed keys and two block hashes, the compressed public keys, the
shared secret, the block hash in both byte orders, the pair value, the
role bit, and the initiator, plus the ranking a node holding two of the
entries derives (R-4.4 to R-4.7, R-7.4). Implementations are expected to
decode every valid vector, reproduce its encoding byte for byte, reject
every invalid vector, and reproduce every pair value and role. These are
wire-format and arithmetic checks, not authorization to use a decoded
endpoint; routability and the other checks in R-2.1, R-5.1, and R-7.3
still apply. The vectors use documentation address ranges.

## Changelog

* 0.1.0 (2026-10-16): initial draft, from "option 6" in the Delving
  thread: announcements with short-lived keys over address relay, rounds
  triggered by block arrival, pair values from ECDH and the block hash,
  lowest-three ranking with roles from the pair value, source-bucketed
  table, parent-block eligibility rule, two-minute pending attempts,
  optional table synchronisation on `getaddr`.

## Appendix: state machines

See [`bip-tcp-holepunch-coordinatorless/state-machines.md`](bip-tcp-holepunch-coordinatorless/state-machines.md)
for the session, listener, node, key, table, and round state tables.
